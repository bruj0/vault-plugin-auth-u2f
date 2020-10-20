#!/bin/bash -x
set +e
kill -TERM $(pidof vault)
export  VAULT_ADDR=http://127.0.0.1:8200
unset VAULT_TOKEN
/usr/local/bin/vault server -dev -dev-listen-address=0.0.0.0:8200 -dev-root-token-id=root -dev-plugin-dir=../plugins -log-level=trace > test.log 2>&1 &
sleep 3s
vault auth enable u2f
sleep 1s
vault write auth/u2f/roles/my-role token_policies="polA,polB"
sleep 1s
vault read auth/u2f/roles/my-role


# 2020/10/02 15:49:01 1 registerRequest: &{AppID:https://lxc1:3483 RegisterRequests:[{Version:U2F_V2 Challenge:hnB_GnCw0nNOf79YBIoMJAV8LlVKBvJ3mzGnQsT37Lk AppID:https://lxc1:3483}] RegisteredKeys:[]}
# 2020/10/02 15:49:07 registerResponse rbody:
# 2020/10/02 15:49:07 Registration success: &{
#    KeyHandle:HHmjDWjzA93JsEbJIrjiUu3fcgQE5vNhEEKEFFzzTcA5zkXf5pmAs7BQFGvQtmE0up2hD7bHM5UqCzyshAcN1w 
#    PublicKey:BKjs4jnO5DysSCuAaYuXBmRkugu3InS5oP2sU5ynRXQk1kOj0qZpvSpAVt0hTx54_yxZVS-hhK7L_CQZ-61guJ4 
#    Counter:0 
#    Certificate:MIIBNTCB3KADAgECAgsAswlxGtpY2KwQUzAKBggqhkjOPQQDAjAVMRMwEQYDVQQDEwpVMkYgSXNzdWVyMBoXCzAwMDEwMTAwMDBaFwswMDAxMDEwMDAwWjAVMRMwEQYDVQQDEwpVMkYgRGV2aWNlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGJiPsRE4Hz6GkuwOWDdZczFAInq-NBGr_2Go4oeLWScBeydjYdroCk0_Cd3p40eE5L8aIJ0WUcQHlEmiSgdT6aMXMBUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwCgYIKoZIzj0EAwIDSAAwRQIhAMGjpo4vFqchRicFf2K7coyeA-ehumLQRlJORW0sLz9zAiALX3jlEaoYEp9vI22SEyJ9krTmft9T6BbfsF2dyLkP3g
#    }
# 2020/10/02 15:49:17 authenticateRequest: &{AppID:https://lxc1:3483 Challenge:Tx5lIDtbGNeFdDHZytLG4MoHvG2-kVR8b1m2tjr__h4 RegisteredKeys:[{Version:U2F_V2 KeyHandle:HHmjDWjzA93JsEbJIrjiUu3fcgQE5vNhEEKEFFzzTcA5zkXf5pmAs7BQFGvQtmE0up2hD7bHM5UqCzyshAcN1w Transports: AppID:}]}
# 2020/10/02 15:49:20 signResponse: {KeyHandle:HHmjDWjzA93JsEbJIrjiUu3fcgQE5vNhEEKEFFzzTcA5zkXf5pmAs7BQFGvQtmE0up2hD7bHM5UqCzyshAcN1w SignatureData:AQAAAAQwRQIhAKTb2qrXrQ5D4xH17rFvIzdT3i-2KnDsMtdMuL2KDy8eAiAuzrWNaFrIOhgMDv4QMgnsPdu_73FYjOwsz8fo3eNPyg ClientData:eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoiVHg1bElEdGJHTmVGZERIWnl0TEc0TW9IdkcyLWtWUjhiMW0ydGpyX19oNCIsIm9yaWdpbiI6Imh0dHBzOi8vbHhjMTozNDgzIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJleHRyYV9rZXlzX21heV9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0}
# 2020/10/02 15:49:20 newCounter: 4