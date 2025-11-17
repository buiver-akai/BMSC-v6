# bench_aead.py — demo版 vs prod版の簡易ベンチ
import os, time, importlib

def bench(enc, dec, name):
    K=os.urandom(32); IV=b"BMSCv6-IV00"; aad=b"bench"; data=os.urandom(1_000_000)
    t0=time.perf_counter(); n,c,t=enc(data,K,IV,aad=aad); t1=time.perf_counter()
    p=dec(n,c,t,K,IV,aad=aad); t2=time.perf_counter(); assert p==data
    enc_ms=(t1-t0)*1000; dec_ms=(t2-t1)*1000
    mbps_enc=(len(data)/1_048_576)/((t1-t0) if (t1-t0)>0 else 1e-9)
    mbps_dec=(len(data)/1_048_576)/((t2-t1) if (t2-t1)>0 else 1e-9)
    print(f"{name}: enc {enc_ms:.1f} ms ({mbps_enc:.1f} MiB/s), dec {dec_ms:.1f} ms ({mbps_dec:.1f} MiB/s)")

def main():
    try:
        prod=importlib.import_module("bmsc_v6_prod"); bench(prod.bmsc_v6_encrypt, prod.bmsc_v6_decrypt, "prod(XChaCha20-Poly1305)")
    except Exception as e: print("prod ベンチ失敗:", e)
    try:
        demo=importlib.import_module("bmsc_v6"); bench(demo.bmsc_v6_encrypt, demo.bmsc_v6_decrypt, "demo(HMAC-stream)")
    except Exception as e: print("demo ベンチ失敗:", e)

if __name__=="__main__": main()
