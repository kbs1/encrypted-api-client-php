<?php

namespace Kbs1\EncryptedApiClientPhp;

use Kbs1\EncryptedApiBase\Cryptography\{Encryptor, Decryptor};
use Kbs1\EncryptedApiBase\Cryptography\Support\SharedSecrets;

use Kbs1\EncryptedApiClientPhp\Exceptions\{InvalidResponseException, InvalidResponseIdException};

use GuzzleHttp\{Client as GuzzleClient, PrepareBodyMiddleware};
use GuzzleHttp\Psr7\MultipartStream;
use function GuzzleHttp\Psr7\{stream_for, mimetype_from_filename};
use Psr\Http\Message\{RequestInterface, ResponseInterface};

class EncryptedApiMiddleware
{
	protected $guzzleClient, $nextHandler;
	protected $secrets;
	protected $overriddenHeaders = ['content-type', 'content-length', 'transfer-encoding', 'expect'];
	protected $visibleHeaders = ['user-agent', 'host'];
	protected $unmanagedHeaders = [];
	protected $filesOverriddenHeaders = ['content-type', 'content-length'];
	protected $filesVisibleHeaders = false;
	protected $lastRawRequest, $lastRawResponse;
	protected $request_completed = false;
	protected $methodSpoofing = true;

	public function __construct(GuzzleClient $guzzleClient)
	{
		$this->guzzleClient = $guzzleClient;
	}

	public function isRequestCompleted()
	{
		return $this->request_completed;
	}

	public function getLastRawRequest()
	{
		if (!$this->isRequestCompleted())
			throw new \LogicException('Perform a request first.');

		return $this->lastRawRequest;
	}

	public function getLastRawResponse()
	{
		if (!$this->isRequestCompleted())
			throw new \LogicException('Perform a request first.');

		return $this->lastRawResponse;
	}

	public function setNextHandler(callable $nextHandler)
	{
		$this->nextHandler = $nextHandler;
		return $this;
	}

	public function __invoke(RequestInterface $request, array &$options)
	{
		$this->options = $options;
		$this->request_completed = false;
		$request = $this->applyOptions($request, $options);

		if (isset($options['encrypted_api']['multipart']))
			return $this->sendMultipartRequest($request, $options);
		else
			return $this->sendJsonRequest($request, $options);
	}

	protected function applyOptions(RequestInterface $request, array &$options)
	{
		if ($this->methodSpoofing) {
			if (isset($options['encrypted_api']['spoofed_method'])) {
				$request = $request->withoutHeader('X-Http-Method-Override');
				$request = $request->withHeader('X-Http-Method-Override', strtoupper($options['encrypted_api']['spoofed_method']));
			} else if (strtolower($request->getMethod()) == 'get' && (!isset($options['encrypted_api']['automatic_method_spoofing']) || $options['encrypted_api']['automatic_method_spoofing'])) {
				$request = $request->withMethod('POST');
				$request = $request->withoutHeader('X-Http-Method-Override');
				$request = $request->withHeader('X-Http-Method-Override', 'GET');
			}
		}

		$this->visibleHeaders = ['user-agent', 'host'];
		if (isset($options['encrypted_api']['visible_headers'])) {
			foreach ((array) $options['encrypted_api']['visible_headers'] as $header) {
				$header = strtolower($header);

				if (in_array($header, $this->overriddenHeaders))
					throw new \InvalidArgumentException($header . ' can not be sent as visible header.');

				if (!in_array($header, $this->visibleHeaders))
					$this->visibleHeaders[] = $header;
			}
		}

		$this->unmanagedHeaders = [];
		if (isset($options['encrypted_api']['unmanaged_headers'])) {
			foreach ((array) $options['encrypted_api']['unmanaged_headers'] as $header) {
				$header = strtolower($header);

				if (in_array($header, $this->overriddenHeaders))
					throw new \InvalidArgumentException($header . ' can not be sent as unmanaged header.');

				if (!in_array($header, $this->unmanagedHeaders))
					$this->unmanagedHeaders[] = $header;
			}
		}

		$this->filesVisibleHeaders = isset($options['encrypted_api']['files_visible_headers']) && $options['encrypted_api']['files_visible_headers'];

		return $request;
	}

	protected function resolveSecrets(array $options)
	{
		$secret1 = $options['encrypted_api']['secret1'] ?? null;
		$secret2 = $options['encrypted_api']['secret2'] ?? null;

		if ($secret1 && $secret2)
			return new SharedSecrets($secret1, $secret2);

		$config = $this->guzzleClient->getConfig('encrypted_api');
		$secret1 = $config['secret1'] ?? null;
		$secret2 = $config['secret2'] ?? null;

		if ($secret1 && $secret2)
			return new SharedSecrets($secret1, $secret2);

		throw new \InvalidArgumentException('Unable to resolve shared secrets for request. Either set default shared secrets for Guzzle client as encrypted_api/secret1 and encrypted_api/secret2 config values, or provide shared secrets under the same keys as request options.');
	}

	protected function sendJsonRequest(RequestInterface $request, $options)
	{
		$secrets = $this->resolveSecrets($options);
		$data = (string) $request->getBody();
		$method = $request->getMethod();
		$uri = (string) $request->getUri();
		// includes Content-Type and other headers if applied by GuzzleHttp\Client applyOptions()
		$headers = $request->getHeaders();

		// transform the headers array into required format and remove any unmanaged headers
		foreach ($headers as $header => $values) {
			if (in_array(strtolower($header), $this->unmanagedHeaders)) {
				unset($headers[$header]);
				continue;
			}

			if (!is_array($values))
				$headers[$header] = [$values];
		}

		$encryptor = new Encryptor($headers, $data, $secrets->getSecret1(), $secrets->getSecret2(), null, $uri, $method);
		$transmit = $encryptor->getTransmit();

		// replace the request body
		$request = $request->withBody(stream_for($transmit));
		$request = $this->recomputeStandardHeaders($request, $options);

		// replace Content-Type header
		$request = $request->withHeader('Content-Type', 'application/json');

		return $this->handleRequest($request, $options, $encryptor->getId(), $secrets);
	}

	protected function sendMultipartRequest(RequestInterface $request, &$options)
	{
		$secrets = $this->resolveSecrets($options);

		// capture main request data
		$main_request = [
			'data' => (string) $request->getBody(),
			'method' => $request->getMethod(),
			'uri' => (string) $request->getUri(),
			'headers' => $request->getHeaders(),
		];

		// transform main request headers array into required format and remove any unmanaged headers
		foreach ($main_request['headers'] as $header => $values) {
			if (in_array(strtolower($header), $this->unmanagedHeaders)) {
				unset($main_request['headers'][$header]);
				continue;
			}

			if (!is_array($values))
				$main_request['headers'][$header] = [$values];
		}

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

			$encryptor = new Encryptor($headers, (string) $contents, $secrets->getSecret1(), $secrets->getSecret2(), null, $main_request['uri'], $main_request['method'], true);
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
				'headers' => $this->filesVisibleHeaders ? $file_headers + ($field['headers'] ?? []) : $file_headers,
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
		$encryptor = new Encryptor($main_request['headers'], $main_request['data'], $secrets->getSecret1(), $secrets->getSecret2(), null, $main_request['uri'], $main_request['method'], $uploads);
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

		return $this->handleRequest($request, $options, $encryptor->getId(), $secrets);
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

	protected function handleRequest(RequestInterface $request, $options, $id, $secrets)
	{
		// see which headers should be visible - some of these headers may also be unmanaged
		$visibleHeaders = array_merge($this->overriddenHeaders, $this->visibleHeaders, $this->unmanagedHeaders);
		foreach ($request->getHeaders() as $header => $values) {
			$name = strtolower($header);

			if (!in_array($name, $visibleHeaders))
				$request = $request->withoutHeader($name);
		}

		$this->lastRawRequest = clone $request;
		$fn = $this->nextHandler;

		return $fn($request, $options)->then(function (ResponseInterface $response) use ($id, $secrets) {
			$this->lastRawResponse = clone $response;

			$decryptor = new Decryptor((string) $response->getBody(), $secrets->getSecret1(), $secrets->getSecret2());
			$original = $decryptor->getOriginal();

			// check if this is a valid response
			if ($original['url'] !== null || $original['method'] !== null || $original['uploads'] !== null)
				throw new InvalidResponseException;

			// replace response body
			$response = $response->withBody(stream_for($original['data']));

			// replace headers transmitted encrypted
			foreach ($original['headers'] as $name => $values) {
				$response = $response->withoutHeader($name);

				foreach ($values as $value)
					$response = $response->withAddedHeader($name, $value);
			}

			// check response haders after decryption (even Location header is transmitted securely by default)
			if (substr($response->getStatusCode(), 0, 1) == '3' && $response->hasHeader('Location'))
				$this->methodSpoofing = false; // spoof only once, let Guzzle handle redirect request method
			else
				$this->methodSpoofing = true; // spoof next request if asked to

			$this->request_completed = true;

			// check we got back the same request id as we sent
			// do this as last step, since it still might be possible the response was decrypted, in which case
			// the server used the same pair of secrets to send the response, but failed to parse our payload
			// for some reason. Catching this exception will still allow us to retrieve the decrypted response.
			if ($original['id'] !== $id)
				throw new InvalidResponseIdException;

			return $response;
		});
	}
}
