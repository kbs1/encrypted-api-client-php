<?php

namespace Kbs1\EncryptedApiClientPhp;

use GuzzleHttp\Client as GuzzleClient;
use function GuzzleHttp\Psr7\stream_for;

class Client
{
	public static function prepare(GuzzleClient $guzzle_client)
	{
		$middleware = new EncryptedApiMiddleware($guzzle_client);
		$stack = $guzzle_client->getConfig('handler');

		// TODO: check if encrypted api is already added
		$stack->push(function (callable $handler) use ($middleware) {
			$middleware->setNextHandler($handler);
			return $middleware;
		}, 'encrypted_api');

		return $middleware;
	}

	public static function createDefaultGuzzleClient($secret1 = null, $secret2 = null, &$middleware = null)
	{
		$guzzle_client = new GuzzleClient([
			'http_errors' => false,
			'encrypted_api' => [
				'secret1' => $secret1,
				'secret2' => $secret2,
			],
		]);

		$middleware = self::prepare($guzzle_client);
		return $guzzle_client;
	}

	public static function prepareOptions($options)
	{
		if (!is_array($options))
			return $options;

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

		return $options;
	}
}
