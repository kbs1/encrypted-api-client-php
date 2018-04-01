<?php

namespace Kbs1\EncryptedApiClientPhp;

use Kbs1\EncryptedApiBase\Cryptography\{Encryptor, Decryptor};
use Kbs1\EncryptedApiBase\Cryptography\Support\SharedSecrets;

use Kbs1\EncryptedApiClientPhp\Exceptions\{InvalidResponseException, InvalidResponseIdException};

use Psr\Http\Message\{RequestInterface, ResponseInterface};
use GuzzleHttp\PrepareBodyMiddleware;
use function GuzzleHttp\Psr7\{stream_for, mimetype_from_filename};
use GuzzleHttp\Psr7\MultipartStream;

class EncryptedApiMiddleware
{
	protected $next_handler, $request_completed = false, $options;
	protected $secrets;
	protected $overriddenHeaders = ['content-type', 'content-length', 'transfer-encoding', 'expect'];
	protected $unencryptedHeaders = ['user-agent', 'host'];
	protected $filesOverriddenHeaders = ['content-type', 'content-length'];
	protected $sendFilesHeadersUnencrypted = false;
	protected $request, $raw_response, $response;

	public function __construct(SharedSecrets $secrets)
	{
		$this->secrets = $secrets;
	}

	public function setNextHandler(callable $next_handler)
	{
		$this->next_handler = $next_handler;
		return $this;
	}

	public function __invoke(RequestInterface $request, array &$options)
	{
		$this->options = $options;
		$this->request_completed = false;

		if (isset($options['encrypted_api']['multipart']))
			return $this->sendMultipartRequest($request, $options);
		else
			return $this->sendJsonRequest($request, $options);
	}

	public function withPlainHeader($name)
	{
		$name = strtolower($name);

		if (in_array($name, $this->overriddenHeaders))
			throw new \InvalidArgumentException($name . ' can not be sent as a plain header.');

		if (!in_array($name, $this->unencryptedHeaders))
			$this->unencryptedHeaders[] = $name;
	}

	public function withoutPlainHeader($name)
	{
		$name = strtolower($name);
		if (($key = array_search($name, $this->unencryptedHeaders)) !== false) {
			unset($this->unencryptedHeaders[$key]);
			$this->unencryptedHeaders = array_values($this->unencryptedHeaders);
		}
	}

	public function setUnencryptedFilesHeaders($value)
	{
		$this->sendFilesHeadersUnencrypted = (boolean) $value;
	}

	public function isRequestCompleted()
	{
		return $this->request_completed;
	}

	public function getRequest()
	{
		if (!$this->isRequestCompleted())
			throw new \LogicException('Perform a request first.');

		return $this->request;
	}

	public function getRequestOption($key = null)
	{
		if ($key === null)
			return $this->options;

		return $this->options[$key] ?? null;
	}

	public function getRawResponse()
	{
		if (!$this->isRequestCompleted())
			throw new \LogicException('Perform a request first.');

		return $this->raw_response;
	}

	public function getResponse()
	{
		if (!$this->isRequestCompleted())
			throw new \LogicException('Perform a request first.');

		return $this->response;
	}

	protected function sendJsonRequest(RequestInterface $request, $options)
	{
		$data = (string) $request->getBody();
		$method = $request->getMethod();
		$uri = (string) $request->getUri();
		// includes Content-Type and other headers if applied by GuzzleHttp Client applyOptions()
		$headers = $request->getHeaders();

		// transform the headers array into required format
		foreach ($headers as $header => $values)
			if (!is_array($values))
				$headers[$header] = [$values];

		$encryptor = new Encryptor($headers, $data, $this->secrets->getSecret1(), $this->secrets->getSecret2(), null, $uri, $method);
		$transmit = $encryptor->getTransmit();

		// replace the request body
		$request = $request->withBody(stream_for($transmit));
		$request = $this->recomputeStandardHeaders($request, $options);

		// replace Content-Type header
		$request = $request->withHeader('Content-Type', 'application/json');

		return $this->handleRequest($request, $options, $encryptor->getId());
	}

	protected function sendMultipartRequest(RequestInterface $request, &$options)
	{
		// capture main request data
		$main_request = [
			'data' => (string) $request->getBody(),
			'method' => $request->getMethod(),
			'uri' => (string) $request->getUri(),
			'headers' => $request->getHeaders(),
		];

		// transform main request headers array into required format
		foreach ($main_request['headers'] as $header => $values)
			if (!is_array($values))
				$main_request['headers'][$header] = [$values];

		// build multipart and uploads array
		$uploads = [];
		foreach ($options['encrypted_api']['multipart'] as $field) {
			$name = $field['name'];
			$filename = $field['filename'] ?? null;
			$contents = stream_for($field['contents'] ?? '');
			$headers = $field['headers'] ?? [];

			// try to set filename as guzzle natively would
			if (empty($filename)) {
				$uri = $contents->getMetadata('uri');
				if (substr($uri, 0, 6) !== 'php://')
					$filename = $uri;
			}

			// transform file headers array into required format
			foreach ($headers as $header => $values)
				if (!is_array($values))
					$headers[$header] = [$values];

			// try to guess Content-Type if one was not provided
			$lowercase_headers = array_change_key_case($headers);
			if (!isset($lowercase_headers['content-type']) && !empty($filename) && $type = mimetype_from_filename($filename))
				$headers['Content-Type'] = [$type];

			// compute Content-Length if possible
			if ($contents->getSize())
				$headers['Content-Length'] = [$contents->getSize()];

			$encryptor = new Encryptor($headers, (string) $contents, $this->secrets->getSecret1(), $this->secrets->getSecret2(), null, $main_request['uri'], $main_request['method'], true);
			$transmit = $encryptor->getTransmit();

			$tmp_file = tmpfile();
			fwrite($tmp_file, $transmit);

			$file_headers = [
				'Content-Type' => 'application/json',
				'Content-Length' => (string) strlen($transmit),
			];

			$multipart[] = [
				'name' => $field['name'],
				'contents' => $tmp_file,
				'headers' => $this->sendFilesHeadersUnencrypted ? $file_headers + ($field['headers'] ?? []) : $file_headers,
				'filename' => $filename,
			];

			if ($this->isValidFileFormName($name))
				$uploads[] = [
					'name' => $name,
					'filename' => basename($filename === '0' ? stream_get_meta_data($tmp_file)['uri'] : $filename), // overcome guzzle MultipartStream bug that overrides filename if filename is '0' ('empty' check will pass)
					'signature' => $encryptor->getSignature(),
				];
		}

		unset($encryptor, $transmit, $options['encrypted_api']['multipart']);

		// prepare main encrypted payload body
		$encryptor = new Encryptor($main_request['headers'], $main_request['data'], $this->secrets->getSecret1(), $this->secrets->getSecret2(), null, $main_request['uri'], $main_request['method'], $uploads);
		$transmit = $encryptor->getTransmit();

		// prepend multipart array, first entry is main encrypted payload with all standard form fields
		array_unshift($multipart, [
			'name' => 'request',
			'contents' => $transmit,
			'headers' => [
				'Content-Type' => 'application/json',
				'Content-Length' => (string) strlen($transmit),
			],
		]);

		// replace the request body
		$request = $request->withBody(new MultipartStream($multipart));
		$request = $this->recomputeStandardHeaders($request, $options);

		// replace Content-Type header
		$request = $request->withHeader('Content-Type', 'multipart/form-data; boundary=' . $request->getBody()->getBoundary());

		return $this->handleRequest($request, $options, $encryptor->getId());
	}

	protected function recomputeStandardHeaders($request, $options)
	{
		// unset headers which PrepareBodyMiddleware handles
		$request = $request->withoutHeader('Content-Type');
		$request = $request->withoutHeader('Content-Length');
		$request = $request->withoutHeader('Expect');
		$request = $request->withoutHeader('Transfer-Encoding');

		// recompute standard plain request headers
		$prepare_body = new PrepareBodyMiddleware(function (RequestInterface $request, $options) {
			return $request;
		});

		return $prepare_body($request, $options);
	}

	protected function isValidFileFormName($name)
	{
		$in_array = $at_least_one_array = false;

		for ($i = 0; $i < strlen($name); $i++) {
			if ($name{$i} === '[') {
				if ($in_array)
					return false;
				$in_array = $at_least_one_array = true;
			} else if ($name{$i} === ']') {
				if (!$in_array)
					return false;
				$in_array = false;
			} else if (!$in_array && $at_least_one_array) {
				return false;
			}
		}

		return !$in_array;
	}

	protected function handleRequest(RequestInterface $request, $options, $id)
	{
		// see which headers should be unencrypted - all headers are always also sent as encrypted,
		// their values override any unencrypted values upon request decryption by the server
		$unencryptedHeaders = array_merge($this->overriddenHeaders, $this->unencryptedHeaders);
		foreach ($request->getHeaders() as $header => $values) {
			$name = strtolower($header);

			if (!in_array($name, $unencryptedHeaders))
				$request = $request->withoutHeader($name);
		}

		$this->request = $request;
		$fn = $this->next_handler;

		return $fn($request, $options)->then(function (ResponseInterface $response) use ($request, $options, $id) {
			$this->raw_response = clone $response;

			$decryptor = new Decryptor((string) $response->getBody(), $this->secrets->getSecret1(), $this->secrets->getSecret2());
			$original = $decryptor->getOriginal();

			// check if this is a valid response
			if ($original['url'] !== null || $original['method'] !== null || $original['uploads'] !== null)
				throw new InvalidResponseException;

			// check we got back the same request id as we sent
			if ($original['id'] !== $id)
				throw new InvalidResponseIdException;

			// replace response body
			$response = $response->withBody(stream_for($original['data']));

			// append decrypted headers transmitted securely
			foreach ($original['headers'] as $name => $values) {
				$response = $response->withoutHeader($name);

				foreach ($values as $value)
					$response = $response->withAddedHeader($name, $value);
			}

			$this->request_completed = true;
			return $this->response = $response;
		});
	}
}
