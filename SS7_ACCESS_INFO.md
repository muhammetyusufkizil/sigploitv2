# SS7 Network Access Guide

## Is it possible to "find" an open SS7 Port?
SS7 (Signaling System No. 7) is a private, closed network used by telecom operators. Unlike the Wi-Fi or public internet, you cannot simply scan an IP range to find an entry point.

### Legitimate Access Methods
To perform real SS7 penetration testing, you must have **Authorized Access**. This is typically obtained in two ways:

1.  **Mobile Network Operator (MNO) Agreement:**
    - You work for a Telecom Operator.
    - You are a security auditor hired by an Operator.
    - They provide you with a **VPN connection** to their STP (Signal Transfer Point).
    - They whitelist your **Global Title (GT)** address.

2.  **SS7 Hub / Signaling Provider:**
    - Usage of services from authorized Signaling Providers (e.g., for SMS aggregation).
    - These providers lease access to the SS7 network for business purposes.
    - **Cost:** Typically very expensive (Thousands of dollars/month) + strict KYC (Identity Verification).

### The "Leak" Misconception
- Searching for "leaks" or "open ports" on the SS7 network without authorization is **illegal**.
- SigPloit is designed to test **your own** infrastructure or infrastructure you have permission to audit.

## SigPloit's Role
SigPloit acts as the **Client Software**. Even if you have the software (the car), you still need the road (SS7 Network Connection) to drive it.

**Currently, we are fixing the "Car" (SigPloit) so that when you eventually get "Road Access" (Authorized VPN), everything will work perfectly.**
