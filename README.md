# MonitorLogWMI# 🧩 WMI Activity Log Monitor (ETW + Log Rotation)

---

## 🧱 Giới thiệu

Chương trình **WMI Activity Monitor** sử dụng **ETW (Event Tracing for Windows)** để **giám sát các sự kiện của provider Microsoft-Windows-WMI-Activity** — đây là provider chịu trách nhiệm ghi lại các truy vấn, thực thi lệnh, hoặc hoạt động WMI trên Windows.

Công cụ này được thiết kế cho mục đích **phân tích bảo mật và điều tra forensics**, giúp bạn theo dõi xem **ứng dụng nào đang sử dụng WMI**, **thực thi lệnh nào**, và **khi nào nó xảy ra**.

---

## 🧰 Chức năng chính

- 🧩 **Theo dõi realtime** các sự kiện WMI (`Microsoft-Windows-WMI-Activity`).
- 🧠 **Trích xuất chi tiết sự kiện**: EventID, ProcessID, ThreadID, Opcode, Task, Level, Keywords...
- 📜 **Ghi log ra file**:  
  `C:\Windows\Temp\WMI_Monitor.log`
- ♻️ **Cơ chế log rotation tự động**:
  - Khi log vượt quá **10 MB**, file cũ được lưu thành `WMI_Monitor.0.log`, `WMI_Monitor.1.log`, ...
  - Giữ tối đa **4 bản log cũ**.
- 🔐 **Thread-safe logging** với `CRITICAL_SECTION`.
- 🧵 **Theo dõi bằng thread riêng** sử dụng `OpenTrace` + `ProcessTrace`.
- 🧼 **Tự động dọn session ETW** khi dừng (Ctrl + C).

---
