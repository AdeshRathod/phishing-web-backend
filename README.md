# Phishing URL Detection Backend 🚀

A Flask API for detecting phishing websites using a machine learning model trained on real-world datasets.

---

## 🚀 How to Run

1. **Create a virtual environment (optional but recommended):**

   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/macOS
   venv\Scripts\activate     # Windows

   if didnt work follow the below command

   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

   venv\Scripts\Activate.ps1


   ```

   pip install -r requirements.txt

2. Train Your model

   run below command

   python train_model.py

3. Start the server

   python app.py
