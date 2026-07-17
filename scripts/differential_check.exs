# Differential check against Python Structured Fields and hashlib.
#
# Usage:
#
#   python3 -m pip install http-sfv
#   mix run scripts/differential_check.exs
#
# This is dev-only and intentionally not wired into CI.

py = ~S'''
import base64, hashlib, sys

try:
    import http_sfv
except Exception:
    print("SKIP no http_sfv")
    sys.exit(0)

header = sys.argv[1].encode()
body = base64.b64decode(sys.argv[2])

dictionary = http_sfv.Dictionary()
dictionary.parse(header)

for name, item in dictionary.items():
    value = item.value if hasattr(item, "value") else item
    if not isinstance(value, bytes):
        print("FAIL non-binary value for %s" % name)
        sys.exit(1)

    if name == "sha-256":
        expected = hashlib.sha256(body).digest()
    elif name == "sha-512":
        expected = hashlib.sha512(body).digest()
    else:
        continue

    if value != expected:
        print("FAIL %s" % name)
        sys.exit(1)

print("OK")
'''

for _ <- 1..200 do
  body = :crypto.strong_rand_bytes(:rand.uniform(512) - 1)
  {:ok, header} = HTTPDigest.content_digest(body, algorithms: [:sha256, :sha512])

  case System.cmd("python3", ["-c", py, header, Base.encode64(body)], stderr_to_stdout: true) do
    {"OK\n", 0} ->
      :ok

    {"SKIP no http_sfv\n", 0} ->
      IO.puts("Skipping: install Python package http-sfv to run the differential check.")
      System.halt(0)

    {output, status} ->
      IO.puts("Differential check failed with status #{status}:")
      IO.puts(output)
      IO.puts("Header: #{header}")
      IO.puts("Body base64: #{Base.encode64(body)}")
      System.halt(1)
  end
end

IO.puts("Differential check passed.")
