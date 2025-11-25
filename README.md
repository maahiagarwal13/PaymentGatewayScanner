# Payment Gateway Detection Tool

A lightweight, security-focused Java tool that scans webpages to identify integrated payment gateways such as **Razorpay**, **Paytm**, **Stripe**, **PhonePe**, and others.  
This tool parses HTML content using **Jsoup** and inspects embedded scripts, form actions, and metadata to detect payment gateway integrations or suspicious payment elements.

---

## 🚀 Features
- Detects multiple popular payment gateway providers  
- Uses **Jsoup** for robust HTML parsing  
- Utilizes **Java HttpClient** for HTTP requests  
- Signature-based pattern matching for accurate detection  
- Helps flag **fake or fraudulent payment pages**  
- Simple, fast, and easy to integrate into security audits

---

## 🧠 How It Works
1. The tool fetches the webpage HTML using `HttpClient`.
2. Jsoup parses the HTML DOM structure.
3. It searches for:
   - `<script>` tags referencing gateway SDKs  
   - Payment-related form actions  
   - Known gateway keywords in JS files  
   - Embedded payment button identifiers  
4. A final report is generated indicating:
   - Detected gateways  
   - Confidence indicators  
   - Suspicious elements (if any)

---

## 📂 Tech Stack
- **Java 17+**  
- **Jsoup** (HTML Parser)  
- **Java.net HttpClient**  
- (Optional) Logging Framework like SLF4J

---

## 📦 Project Structure
