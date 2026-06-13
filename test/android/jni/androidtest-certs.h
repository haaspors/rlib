/* Cert material for the Android instrumented trust-store test (test/android).
 *
 * Generated with openssl: two independent self-signed roots and leaves under
 * each, fixed 2015-01-01..2125-01-01 validity. androidtest_root is bundled as an
 * app trust anchor (network_security_config.xml), so leaf_server/leaf_client
 * verify OK via the platform X509TrustManager; root_alt is NOT trusted, so
 * leaf_alt yields a deterministic UNTRUSTED. Regenerate via
 * test/android/certs/gen-androidtest-certs.sh.
 */
#ifndef __R_ANDROIDTEST_CERTS_H__
#define __R_ANDROIDTEST_CERTS_H__

static const rchar at_root_pem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDPDCCAiSgAwIBAgIUEj1IlIZWsjitL4ylDqa1mwnwzywwDQYJKoZIhvcNAQEL\r\n"
  "BQAwIzEhMB8GA1UEAwwYcmxpYiBBbmRyb2lkVGVzdCBSb290IENBMCAXDTE1MDEw\r\n"
  "MTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAjMSEwHwYDVQQDDBhybGliIEFuZHJv\r\n"
  "aWRUZXN0IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCb\r\n"
  "x2oxPvMWbHayL6Z/jS0dV4/PlHrZ6oGenJxf4XoBzIxBVED2s0lEU89TnyHe1Lmm\r\n"
  "+t1De8nDTvofj8EBJWricHcpx/vJyE0yQ07xpUH3Kpcxu44ltAdVUTJkRD7+xwL7\r\n"
  "1fmI28uqZEhVYOde11kg8zyZyJp3MCmvUYCdUcNVC+difJbhnI89RyDfDgYlYj7t\r\n"
  "e2gXx5iHqbXOa/xZJfSzXR9uq1qLmVFN2LfG7kl6IO87i/xz2DFHHzQMChhdYiEa\r\n"
  "vcKwC9U2XRkt8uHspatBBKvdBBFQ5CEnM/om2+Ygeu056kRFQ+e7ZD50PZ6wn1wW\r\n"
  "yli+WvI1yxDT1Q092pgHAgMBAAGjZjBkMB0GA1UdDgQWBBRj1uV2Zk3hcqFR2k6R\r\n"
  "NnZVglNGzzAfBgNVHSMEGDAWgBRj1uV2Zk3hcqFR2k6RNnZVglNGzzASBgNVHRMB\r\n"
  "Af8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEA\r\n"
  "X4+DrWrxWcIpoKy4ZW3eAn5rrPytoVXoqPxXaDwSYbYG34GEbfHry6IlGH/8cwou\r\n"
  "Srnj93fhpSYzp3f5ytuIWqJ0qWWOGwWFLWEd1OygKirsJCRnd4bAyh9bUcReVfkG\r\n"
  "8v4fgHcO1CF7Rzmzl0EkOY7GYukT08sPyrBTh0hxynxKnQMMKJrzy5Q2Gf+ITZZW\r\n"
  "QgOEAS1SRJJAJhO8PQTJ6q3Ng3piDC0adqzHEIbuW3euzoo3TlcvoL8efSW5Aw6j\r\n"
  "N0kOdEx7LD/AmzV5qQKWQhWEdJulViQqEgwGjoTWSRB4EhsyosvLdUjzK6upzmfY\r\n"
  "7Ro1/uV+kux/0wHEMtgupA==\r\n"
  "-----END CERTIFICATE-----\r\n"
;

static const rchar at_leaf_server_pem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDWjCCAkKgAwIBAgIUO6pgvmNdL1BSlPjDZ7ThLHm35vQwDQYJKoZIhvcNAQEL\r\n"
  "BQAwIzEhMB8GA1UEAwwYcmxpYiBBbmRyb2lkVGVzdCBSb290IENBMCAXDTE1MDEw\r\n"
  "MTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Qw\r\n"
  "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPbIm16R+4f+ifR6OKRMQt\r\n"
  "Ft34gheRiXrvXNEHh7dzkslgOfiKnmiyzPeaGMvcjtynAN070KXAPpDBVz7rMlZM\r\n"
  "a2LUc0AMWdui7FcVLYjXa7pUERe13YVfp8alGiYe3qxt616k11ibIak8reNkq3Zw\r\n"
  "VitP66w54k7pBtFSoNLMf0a2NaaIH4Dj/zKIXKvlmNtufrv9KkYs9Viv613uFxSW\r\n"
  "pFmLUC0hL/rluAYdCzwSaOHEmvvXq4zxEuJNMarL6P3JDymt6uJUtBF7mHLxcVmL\r\n"
  "lsGhyNeI2mAHEWj3V4hwfpACcL3VKklg+5sJa+ODDe09KIjyrOr4oPCUnSrLGgo5\r\n"
  "AgMBAAGjgZIwgY8wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l\r\n"
  "BAwwCgYIKwYBBQUHAwEwGgYDVR0RBBMwEYIJbG9jYWxob3N0hwR/AAABMB0GA1Ud\r\n"
  "DgQWBBRzoy/EOjWIcal0nIp7tPVwSoXqmjAfBgNVHSMEGDAWgBRj1uV2Zk3hcqFR\r\n"
  "2k6RNnZVglNGzzANBgkqhkiG9w0BAQsFAAOCAQEABF5p6pRpr2GuPO6Fj8QYAkqd\r\n"
  "DQVDo6egjViPYTTqyJIvLC5zJzrWF84aF1iYLyL7qzf5Hqm77Hb+96LgdLVlTW1X\r\n"
  "Z01xiPBlyXtDPfCOB0TMA68vxsxjZ0cSBnkxZwVrk5hney8ix/rVX8fjGTbH9CPm\r\n"
  "RsG+o4ExpuS0kq82RbjtulmKHhl9EmDTufKCRxmfgyPejclr+S0qrqz6ZMMZ2j1i\r\n"
  "a4PAdvgZfU563TFCYbDLmgVX7tlEYc1uuj7bXsN3en1SeaZWnwbTc+rayPOsdHI0\r\n"
  "MmAsha5KPWuKLgpnYPxKWEmWrJPx0qu7E4HMWZb18yOc0irhddIXs+FnnDYx5A==\r\n"
  "-----END CERTIFICATE-----\r\n"
;

static const rchar at_leaf_client_pem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDaDCCAlCgAwIBAgIUO6pgvmNdL1BSlPjDZ7ThLHm35vUwDQYJKoZIhvcNAQEL\r\n"
  "BQAwIzEhMB8GA1UEAwwYcmxpYiBBbmRyb2lkVGVzdCBSb290IENBMCAXDTE1MDEw\r\n"
  "MTAwMDAwMFoYDzIxMjUwMTAxMDAwMDAwWjAiMSAwHgYDVQQDDBdybGliIEFuZHJv\r\n"
  "aWRUZXN0IENsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK0q\r\n"
  "nz+2NTA5ZJSeorWmThFy498EX7hRAWbh5dL0jkd9sfg5DcXJNBfdkcMn78T4+HEH\r\n"
  "lnnA1CT9HoZvMrMsiRy5sRrktp1bguAjdh4wcI9d16wJZ22EAyDTXxqdp1r3JOV/\r\n"
  "TOBcjXQI24pyxPg9Pct3dawrhn7/U39ohVo8Nd5M5u0Ru11GubWk61r0QRmfqxz2\r\n"
  "Me9wLYFLDQwhXwjM+RCOIeGQ5R9O99/IJMJ5TVDZZTr+iX3cs2BAgT4kLMk9zlFr\r\n"
  "u98Da5IDI6qDF0n2zY7tn6nytdmzW3xWPKPJyO6HOaLdhsp8sgBD9GG7MZ5hLzOx\r\n"
  "GzUl2K0f1QGN90kEoJcCAwEAAaOBkjCBjzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB\r\n"
  "/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAjAaBgNVHREEEzARgglsb2NhbGhv\r\n"
  "c3SHBH8AAAEwHQYDVR0OBBYEFMI/RA2u9fhhuFE+m2mPeY6lStLrMB8GA1UdIwQY\r\n"
  "MBaAFGPW5XZmTeFyoVHaTpE2dlWCU0bPMA0GCSqGSIb3DQEBCwUAA4IBAQCQidHW\r\n"
  "40bvFMcNJpsnPUYOLbRal4vWpq87CmzwslIft73daUUgMZ9w0KrfqUTjAMTddacH\r\n"
  "kshzyIlaMTRwx07k6qLXHS9NRBcJdcssM9iht3n3CFlP7E6AswcTGB/t2dIFgypD\r\n"
  "yV/KF07HPpBtEOOTpLqeeERk/9E9jwEMU7H4rGbdRq7r5OwP6ZTk2L8CBOnnQrTc\r\n"
  "49/LS00QvaZI3kwXo35Tco2w9laskoVzuvAzqfJEFfWP1DOXbrMKdkBhcFDTDQVV\r\n"
  "syzpfRCqk4G1GOc+fTI3VK4bcRx7WJAdvsq6IBqnT7W6Q6BYnxP3ahkEDK2Ac3ux\r\n"
  "KJ4OYafrx0sTECew\r\n"
  "-----END CERTIFICATE-----\r\n"
;

static const rchar at_root_alt_pem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDTDCCAjSgAwIBAgIUEGvyZFAG36xxZLh81owEJdIZG8swDQYJKoZIhvcNAQEL\r\n"
  "BQAwKzEpMCcGA1UEAwwgcmxpYiBBbmRyb2lkVGVzdCBGb3JlaWduIFJvb3QgQ0Ew\r\n"
  "IBcNMTUwMTAxMDAwMDAwWhgPMjEyNTAxMDEwMDAwMDBaMCsxKTAnBgNVBAMMIHJs\r\n"
  "aWIgQW5kcm9pZFRlc3QgRm9yZWlnbiBSb290IENBMIIBIjANBgkqhkiG9w0BAQEF\r\n"
  "AAOCAQ8AMIIBCgKCAQEAtVQjBeJtwKROs1Z0jI14nL26ubRYUlFyR6DSE1OorG3/\r\n"
  "wV6At/Wyma22bkv49FkGBXZZTdV7goE3u5tIiQRyVblaW4cUooc4j6H87BpHWKEm\r\n"
  "3bvHuYP04m8ufpkvhRBU3PQAQtEskLmz52eOGc0M8QvdkjOwZDJbCqPSqqeGe4OH\r\n"
  "yU0fDfzjuazRp1NzoTLBeJqFV5tjo7P7LC0/UFOE3m/fciG6uYEB0dgMyvv4mJ6S\r\n"
  "35Durl4jn9pu8C0vUUJGpacqhQ1Nmk52rOKZtjTioizuAmq3eKcdcNveoagaWUaQ\r\n"
  "eQTeqdNGtL7xMtb71a/0T5e/U+ei3SXyP/8I+fBiCwIDAQABo2YwZDAdBgNVHQ4E\r\n"
  "FgQUwRP3VO8fmcik44posX+kY9wYP4QwHwYDVR0jBBgwFoAUwRP3VO8fmcik44po\r\n"
  "sX+kY9wYP4QwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwDQYJ\r\n"
  "KoZIhvcNAQELBQADggEBAFXFIFhIY1gv6PUSY3OYIGDYSEaFDpNa6c7dFqmnvDLW\r\n"
  "kAdpZ0xDl4YjS4uPhgFnNfxULIvwve3ZMUjteuw1X69FAbha/fEfUOgdReT16SiL\r\n"
  "gJODFcXHhnrkHmGh4igN5Fr+rdtW6HlVVG3NCFtskQ3iSk5bjTAMqgFWZZ9SHnUm\r\n"
  "OV5mlli8zew2POKMKkM8xW/dwwqHZXkQ//FfxOVPZYCPqJLJXBQx/eWm6DVbMQq+\r\n"
  "QvPLtQqbjxoF6sWvvLsBbPVgHay82nOuMCxkv/fR22e24Z6UztriYZmU7wER7g72\r\n"
  "LGLmW7zTVhv1OMK/lEalIF/z7d22+CEsNl8o9AiL/a0=\r\n"
  "-----END CERTIFICATE-----\r\n"
;

static const rchar at_leaf_alt_pem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIDYjCCAkqgAwIBAgIUJkHC8dj/zEdmOT1GnquFHRuAEMQwDQYJKoZIhvcNAQEL\r\n"
  "BQAwKzEpMCcGA1UEAwwgcmxpYiBBbmRyb2lkVGVzdCBGb3JlaWduIFJvb3QgQ0Ew\r\n"
  "IBcNMTUwMTAxMDAwMDAwWhgPMjEyNTAxMDEwMDAwMDBaMBQxEjAQBgNVBAMMCWxv\r\n"
  "Y2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAIb4r97d3dvU\r\n"
  "Y1gWN1IQwjbMwHqpZ6LHGdErfYUu8igPjK/dgOO/s1wUlFlOuTYxTHU5DrUivWMm\r\n"
  "3lbvNgSWWltFYVLpdUK8gZ1U6Mb4uKwb9PYIhWHxsQ2u8X4Z7zPMSosxDut12f0l\r\n"
  "kmg0l01t6ERiXqAUBJOSm+yTDdL7fvjMBw58xE7+X/IdbZJDc+SSIw5MuYLeKN36\r\n"
  "vwjbgpLUQUJZmnt3i8++o+HO91lNCJzt1zAauP2j2hkMFY0MAPlK33dLo1aj0K+6\r\n"
  "hjemk6nDXJDfyNxgW0c3sM8KShVc2Jo3U4u1SaCXZ0jQ/vzyjFafCH3QcFad+Ief\r\n"
  "gfQshlbmcIkCAwEAAaOBkjCBjzAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIF\r\n"
  "oDATBgNVHSUEDDAKBggrBgEFBQcDATAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8A\r\n"
  "AAEwHQYDVR0OBBYEFBQ/JxF9OgO6F4ohFs8cQWmO/JWbMB8GA1UdIwQYMBaAFMET\r\n"
  "91TvH5nIpOOKaLF/pGPcGD+EMA0GCSqGSIb3DQEBCwUAA4IBAQAZUmUomEVswfwC\r\n"
  "rkn+R06lFlav4rAJ8aRMmRK3inPISUTB8axHo5HuTF9hmZURPQCOaevekGk+y2ZK\r\n"
  "lxCMeiMaYQJjEPZ5n8d5OuB3BJ7EWkTthc4DVssvzFUTUjjKjPU36Xx+hc0DM/Xr\r\n"
  "6jBywYiMqu31PnJvNhbkslKYJwxaQNr1dI9Ohh6GvzIX1AHvuAvSeENcFB5OH0Xe\r\n"
  "DSsQTbXLpliEuh5mNvJbtXukb1kjo0QvKt+02LStj5yyo1L+zFuHani7Lid8uULP\r\n"
  "4SJTK2tgQfSX1CE8atmclqal4ac7gk8o5/F51objzqGN6AvzIojk2L8++LyXpJY/\r\n"
  "dYAe5/ZO\r\n"
  "-----END CERTIFICATE-----\r\n"
;

#endif /* __R_ANDROIDTEST_CERTS_H__ */
