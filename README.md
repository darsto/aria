# ARIA cipher

Rust implementation of Korean ARIA cipher.

The cipher itself has certain similarities to AES, but it's a standardized
standalone cipher. This implementation is based on ARIA specification 1.0,
available at KISA webpage:

https://seed.kisa.or.kr/kisa/Board/19/detailView.do

This is an amateur implementation. Use at your risk.

It was tested for validity against test vectors from the above KISA webpage
(see their copy in `resources/ECB`), but there was no security taken into account.
There were also no benchmarks run.

* `imp.rs` contains the actual cipher code
* `lib.rs` provides a cleaner, infallible abstraction

Note: this library has **zero** dependencies!