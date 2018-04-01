<?php

namespace Kbs1\EncryptedApiClientPhp;

use Kbs1\EncryptedApiBase\Cryptography\Support\SharedSecrets;
use GuzzleHttp\Client as GuzzleClient;
use function GuzzleHttp\Psr7\stream_for;

class Client
{
	protected $guzzle_client, $options, $middleware, $secrets;
	protected $automaticMethodSpoofing = true, $spoofedMethod;

	public function __construct(GuzzleClient $guzzle_client, $secret1, $secret2)
	{
		$this->guzzle_client = $guzzle_client;
		$this->secrets = new SharedSecrets($secret1, $secret2);
		$this->middleware = new EncryptedApiMiddleware($this->secrets);

		$stack = $this->guzzle_client->getConfig('handler');
		$stack->push(function (callable $handler) {
			$this->middleware->setNextHandler($handler);
			return $this->middleware;
		}, 'encrypted_api');
	}

	public static function create($secret1, $secret2)
	{
		return new self(new GuzzleClient(['http_errors' => false]), $secret1, $secret2);
	}

	public function __call($method, $arguments)
	{
		// TODO: investigate request and requestAsync
		if (!in_array(strtolower($method), ['request', 'requestAsync']) && method_exists($this->guzzle_client, $method))
			return call_user_func_array([$this->guzzle_client, $method], $arguments);

		if (count($arguments) < 1)
			throw new \InvalidArgumentException('Magic request methods require a URI and optional options array');

		$method = strtolower($method);
		$is_async = substr($method, -5) === 'async';

		if ($is_async)
			$method = substr($method, 0, -5);

		$method = $this->prepareMethodSpoofing($method, $arguments);

		return call_user_func_array([$this->guzzle_client, $method . ($is_async ? 'Async' : '')], $this->getGuzzleParameters($method, $arguments));
	}

	public function automaticMethodSpoofing($value)
	{
		$this->automaticMethodSpoofing = (boolean) $value;
		return $this;
	}

	public function setSpoofedMethod($value)
	{
		$this->spoofedMethod = strtolower($value);
		return $this;
	}

	public function withPlainHeader($name)
	{
		$this->middleware->withPlainHeader($name);
		return $this;
	}

	public function withoutPlainHeader($name)
	{
		$this->middleware->withoutPlainHeader($name);
		return $this;
	}

	public function withManagedHeader($name)
	{
		$this->middleware->withManagedHeader($name);
		return $this;
	}

	public function withoutManagedHeader($name)
	{
		$this->middleware->withoutManagedHeader($name);
		return $this;
	}

	public function setUnencryptedFilesHeaders($value)
	{
		$this->middleware->setUnencryptedFilesHeaders($value);
		return $this;
	}

	public function getGuzzleClient()
	{
		return $this->guzzle_client;
	}

	public function getRequest()
	{
		return $this->middleware->getRequest();
	}

	public function getRequestOption($key = null)
	{
		return $this->middleware->getRequestOption($key);
	}

	public function getRawResponse()
	{
		return $this->middleware->getRawResponse();
	}

	public function getResponse()
	{
		return $this->middleware->getResponse();
	}

	protected function prepareMethodSpoofing($method, &$arguments)
	{
		if ($this->spoofedMethod) {
			$arguments[1]['headers'] = $arguments[1]['headers'] ?? [];
			$arguments[1]['headers']['X-Http-Method-Override'] = strtoupper($this->spoofedMethod);
			return $method;
		}

		if ($this->automaticMethodSpoofing && $method === 'get') {
			$arguments[1]['headers'] = $arguments[1]['headers'] ?? [];
			$arguments[1]['headers']['X-Http-Method-Override'] = 'GET';
			return 'post';
		}

		return $method;
	}

	protected function getGuzzleParameters($method, $arguments)
	{
		$uri = $arguments[0];
		$options = $arguments[1] ?? null;
		$this->options = $options; // save last request options

		if (isset($options['multipart'])) {
			$options['encrypted_api']['multipart'] = $options['multipart'];
			unset($options['multipart'], $options['body']); // this option would override any explicitly passed body in GuzzleHttp\Client applyOptions()

			if (isset($options['form_params']))
				throw new \InvalidArgumentException('You cannot use '
					. 'form_params and multipart at the same time. Use the '
					. 'form_params option if you want to send application/'
					. 'x-www-form-urlencoded requests, and the multipart '
					. 'option to send multipart/form-data requests.');

			$options['form_params'] = [];
			foreach ($options['encrypted_api']['multipart'] as $key => &$field) {
				if (!is_array($field))
					throw new \InvalidArgumentException('Request "multipart" array has invalid format.');

				$name = $field['name'] ?? null;
				if ($name === null) {
					unset($options['encrypted_api']['multipart'][$key]); // remove this entry from multipart data
					continue;
				}

				$contents = $field['contents'] = stream_for($field['contents'] ?? '');
				$filename = $field['filename'] ?? null;

				$field_uri = $contents->getMetadata('uri');
				if (!$filename && $filename !== '0' && substr($field_uri, 0, 6) === 'php://') {
					// this is a standard form parameter, not a file. Append to form_params which will be handled natively by guzzle.
					$options['form_params'] = array_merge_recursive($options['form_params'], [$name => (string) $contents]);
					unset($options['encrypted_api']['multipart'][$key]); // remove this entry from multipart data
				}
			}

			$options['encrypted_api']['multipart'] = array_values($options['encrypted_api']['multipart']);
		}

		return [$uri, $options];
	}
}
