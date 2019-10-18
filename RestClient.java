package com.example;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import okhttp3.ConnectionPool;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * Http client for accessing crypto exchange REST APIs. Example:
 * 
 * <code>
 * RestClient client = new RestClient.Builder("https://api.bitsoda.com")
 *         .authenticate("my-api-key", "my-api-secret")
 *         .build();
 * try {
 *     client.get(Order.class, "/v1/trade/orders/12345", null);
 * }
 * catch (RestClient.ApiException e) {
 * }
 * </code>
 * 
 * Requirements:
 * 
 * jackson;
 * okhttp.
 */
public class RestClient {

	final Logger logger = LoggerFactory.getLogger(getClass());

	final String endpoint;
	final String host;
	final String apiKey;
	final String apiSecret;

	OkHttpClient client;

	public static class Builder {

		final Logger logger = LoggerFactory.getLogger(getClass());

		String scheme;
		String host;
		int port;
		String apiKey;
		String apiSecret;

		int connectTimeout = 3;
		int readTimeout = 3;
		int keepAlive = 30;

		/**
		 * Create builder with api endpoint. e.g. "https://api.bitsoda.com". NOTE: do
		 * not append any PATH.
		 *
		 * @param apiEndpoint The api endpoint.
		 */
		public Builder(String apiEndpoint) {
			logger.info("build RestClient from {}...", apiEndpoint);
			try {
				URI uri = new URI(apiEndpoint);
				if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) {
					throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint);
				}
				if (uri.getPath() != null && !uri.getPath().isEmpty()) {
					throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint);
				}
				this.scheme = uri.getScheme();
				this.host = uri.getHost().toLowerCase();
				this.port = uri.getPort();
			} catch (URISyntaxException e) {
				throw new IllegalArgumentException("Invalid API endpoint: " + apiEndpoint, e);
			}
		}

		public Builder authenticate(String apiKey, String apiSecret) {
			this.apiKey = apiKey;
			this.apiSecret = apiSecret;
			return this;
		}

		public Builder connectTimeout(int connectTimeoutInSeconds) {
			this.connectTimeout = connectTimeoutInSeconds;
			return this;
		}

		public Builder readTimeout(int readTimeoutInSeconds) {
			this.readTimeout = readTimeoutInSeconds;
			return this;
		}

		public Builder keepAlive(int keepAliveInSeconds) {
			this.keepAlive = keepAliveInSeconds;
			return this;
		}

		public RestClient build() {
			OkHttpClient client = new OkHttpClient.Builder()
					// set connect timeout:
					.connectTimeout(this.connectTimeout, TimeUnit.SECONDS)
					// set read timeout:
					.readTimeout(this.readTimeout, TimeUnit.SECONDS)
					// set connection pool:
					.connectionPool(new ConnectionPool(0, this.keepAlive, TimeUnit.SECONDS))
					// do not retry:
					.retryOnConnectionFailure(false).build();
			String endpoint = this.scheme + "://" + this.host;
			if (this.port != (-1)) {
				endpoint = endpoint + ":" + this.port;
			}
			return new RestClient(endpoint, this.host, this.apiKey, this.apiSecret, client);
		}
	}

	RestClient(String endpoint, String host, String apiKey, String apiSecret, OkHttpClient client) {
		this.endpoint = endpoint;
		this.host = host;
		this.apiKey = apiKey;
		this.apiSecret = apiSecret;
		this.client = client;
	}

	public <T> T get(Class<T> clazz, String path, Map<String, String> query) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "GET", path, query, null, null);
	}

	public <T> T get(TypeReference<T> ref, String path, Map<String, String> query) {
		Objects.requireNonNull(ref);
		return request(null, ref, "GET", path, query, null, null);
	}

	public <T> T post(Class<T> clazz, String path, Object body) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "POST", path, null, body, null);
	}

	public <T> T post(Class<T> clazz, String path, Object body, String uniqueId) {
		Objects.requireNonNull(clazz);
		return request(clazz, null, "POST", path, null, body, uniqueId);
	}

	public <T> T post(TypeReference<T> ref, String path, Object body) {
		Objects.requireNonNull(ref);
		return request(null, ref, "POST", path, null, body, null);
	}

	public <T> T post(TypeReference<T> ref, String path, Object body, String uniqueId) {
		Objects.requireNonNull(ref);
		return request(null, ref, "POST", path, null, body, uniqueId);
	}

	<T> T request(Class<T> clazz, TypeReference<T> ref, String method, String path, Map<String, String> query,
			Object body, String uniqueId) {
		if (!path.startsWith("/")) {
			throw new IllegalArgumentException("Invalid path: " + path);
		}
		// build payload:
		StringBuilder payloadToSign = new StringBuilder(1024)
				// method:
				.append(method).append('\n')
				// host:
				.append(host).append('\n')
				// path:
				.append(path).append('\n');
		// query:
		String queryString = null;
		if (query != null) {
			List<String> paramList = new ArrayList<>();
			for (Map.Entry<String, String> entry : query.entrySet()) {
				paramList.add(entry.getKey() + "=" + entry.getValue());
			}
			Collections.sort(paramList);
			queryString = String.join("&", paramList);
			payloadToSign.append(queryString).append('\n');
		} else {
			payloadToSign.append('\n');
		}
		StringBuilder urlBuilder = new StringBuilder(64).append(this.endpoint).append(path);
		if (queryString != null) {
			urlBuilder.append('?').append(queryString);
		}
		final String url = urlBuilder.toString();

		// json body:
		final String jsonBody = body == null ? "" : writeJson(body);

		Request.Builder requestBuilder = new Request.Builder().url(url);
		if ("POST".equals(method)) {
			requestBuilder.post(RequestBody.create(JSON, jsonBody));
		}

		final String timestamp = String.valueOf(System.currentTimeMillis());
		if (uniqueId == null || uniqueId.isEmpty()) {
			uniqueId = UUID.randomUUID().toString().replace("-", "");
		}

		// header:
		List<String> headerList = new ArrayList<>();
		headerList.add(HEADER_API_KEY + ": " + this.apiKey);
		headerList.add(HEADER_API_SIGNATURE_METHOD + ": " + SIGNATURE_METHOD);
		headerList.add(HEADER_API_SIGNATURE_VERSION + ": " + SIGNATURE_VERSION);
		headerList.add(HEADER_API_TIMESTAMP + ": " + timestamp);
		headerList.add(HEADER_API_UNIQUE_ID + ": " + uniqueId);
		Collections.sort(headerList);
		for (String header : headerList) {
			payloadToSign.append(header).append('\n');
		}

		requestBuilder.addHeader(HEADER_API_KEY, this.apiKey);
		requestBuilder.addHeader(HEADER_API_SIGNATURE_METHOD, SIGNATURE_METHOD);
		requestBuilder.addHeader(HEADER_API_SIGNATURE_VERSION, SIGNATURE_VERSION);
		requestBuilder.addHeader(HEADER_API_TIMESTAMP, timestamp);
		requestBuilder.addHeader(HEADER_API_UNIQUE_ID, uniqueId);

		// append body:
		payloadToSign.append(jsonBody);
		// sign:
		String sign = hmacSha256(payloadToSign.toString().getBytes(StandardCharsets.UTF_8),
				apiSecret.getBytes(StandardCharsets.UTF_8));
		requestBuilder.addHeader(HEADER_API_SIGNATURE, sign);

		Request request = requestBuilder.build();
		try {
			return execute(clazz, ref, request);
		} catch (IOException e) {
			throw new RuntimeException("IOException", e);
		}
	}

	<T> T execute(Class<T> clazz, TypeReference<T> ref, Request request) throws IOException {
		logger.info("request: {}...", request.url().url());
		Response response = this.client.newCall(request).execute();
		if (response.code() == 200) {
			try (ResponseBody body = response.body()) {
				logger.info("response 200.");
				String json = body.string();
				if ("null".equals(json)) {
					return null;
				}
				return clazz == null ? readJson(json, ref) : readJson(json, clazz);
			}
		} else if (response.code() == 400) {
			try (ResponseBody body = response.body()) {
				logger.info("response 400.");
				ApiErrorResponse err = readJson(body.string(), ApiErrorResponse.class);
				throw new ApiException(err.error, err.data, err.message);
			}
		} else if (response.code() == 429) {
			// should not happen:
			throw new RuntimeException("Rate limit");
		} else {
			throw new RuntimeException("Http error: " + response.code());
		}
	}

	static final String HEADER_API_KEY = "API-KEY";
	static final String HEADER_API_SIGNATURE = "API-SIGNATURE";
	static final String HEADER_API_SIGNATURE_METHOD = "API-SIGNATURE-METHOD";
	static final String HEADER_API_SIGNATURE_VERSION = "API-SIGNATURE-VERSION";
	static final String HEADER_API_TIMESTAMP = "API-TIMESTAMP";
	static final String HEADER_API_UNIQUE_ID = "API-UNIQUE-ID";

	static final String SIGNATURE_METHOD = "HmacSHA256";
	static final String SIGNATURE_VERSION = "1";

	static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");

	static final String HEX_STRING = "0123456789abcdef";
	static final char[] HEX_CHARS = HEX_STRING.toCharArray();

	/**
	 * Holds ObjectMapper.
	 */
	static final ObjectMapper OBJECT_MAPPER = createObjectMapper();

	private static ObjectMapper createObjectMapper() {
		final ObjectMapper mapper = new ObjectMapper();
		mapper.setSerializationInclusion(JsonInclude.Include.ALWAYS);
		// disabled features:
		mapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
		mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
		// add java8 time support:
		mapper.registerModule(new JavaTimeModule());
		return mapper;
	}

	static String writeJson(Object obj) {
		try {
			return OBJECT_MAPPER.writeValueAsString(obj);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		}
	}

	static <T> T readJson(String str, Class<T> clazz) {
		try {
			return OBJECT_MAPPER.readValue(str, clazz);
		} catch (JsonProcessingException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	static <T> T readJson(String str, TypeReference<T> ref) {
		try {
			return OBJECT_MAPPER.readValue(str, ref);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	static String hmacSha256(byte[] data, byte[] key) {
		SecretKey skey = new SecretKeySpec(key, "HmacSHA256");
		Mac mac;
		try {
			mac = Mac.getInstance("HmacSHA256");
			mac.init(skey);
		} catch (GeneralSecurityException e) {
			throw new RuntimeException(e);
		}
		mac.update(data);
		return toHexString(mac.doFinal());
	}

	static String toHexString(byte[] b) {
		StringBuilder sb = new StringBuilder(b.length * 2);
		for (byte x : b) {
			int hi = (x & 0xf0) >> 4;
			int lo = x & 0x0f;
			sb.append(HEX_CHARS[hi]);
			sb.append(HEX_CHARS[lo]);
		}
		return sb.toString().trim();
	}

	public static class ApiException extends RuntimeException {

		public final String error;
		public final String data;

		public ApiException(String error) {
			super(error.toString());
			this.error = error;
			this.data = null;
		}

		public ApiException(String error, String data) {
			super(error.toString());
			this.error = error;
			this.data = data;
		}

		public ApiException(String error, String data, String message) {
			super(message);
			this.error = error;
			this.data = data;
		}
	}

	public static class ApiErrorResponse {

		public String error;
		public String data;
		public String message;

		public ApiErrorResponse() {
		}

		public ApiErrorResponse(String error, String data, String message) {
			this.error = error;
			this.data = data;
			this.message = message;
		}
	}
}
