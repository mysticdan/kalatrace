# Threat Model

## Deteksi awal

1. Shell dipanggil oleh server process.
2. File sensitif dimodifikasi.
3. SUID/SGID dibuat.
4. Shell membuka outbound connection.

## Non-goal versi awal

1. Packet payload inspection.
2. Full SIEM.
3. Auto-blocking.
4. Dashboard web.
5. Kubernetes controller.
