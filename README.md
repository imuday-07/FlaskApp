# FlaskApp
Bilingual question similarity detection using LSTM with translation support and Flask web interface.

# 🔍 Bilingual Question Similarity Detector

A Flask-based web application that detects semantic similarity between bilingual (English and Telugu) questions using an LSTM model with translation support. This project aims to enhance user experience on Q&A platforms by identifying similar questions and guiding users to ask better ones.

---

## 🚀 Features

- 🔠 **Bilingual Input Support** (English and Telugu)
- 🔁 **LSTM-based Similarity Detection**
- 🌐 **Google Translate Integration**
- 🔒 **Login & Signup System**
- 📜 **Search History Tracking**
- 📊 **Similarity Score Output**
- 🔎 **Smart Google Search Suggestions**
- 🧠 **Trained on Quora Question Pairs Dataset**
- 🌍 **Ngrok Integration for Public Access**

---

## 🧰 Technologies Used

- Python
- Flask
- TensorFlow / Keras
- GloVe Embeddings
- Google Translate API
- HTML/CSS + JavaScript (with dark mode)
- SQLite (for user management and history)
- Ngrok (for deployment in Colab)

---

## 🖼️ Screenshots


![Screenshot 2025-04-25 124050](https://github.com/user-attachments/assets/bd1ab068-4b12-4408-8085-c47cd28e0c38)
![Screenshot 2025-04-25 124109](https://github.com/user-attachments/assets/698b0543-7c8f-4bf0-b05e-e233563aafa4)
![Screenshot 2025-04-25 124456](https://github.com/user-attachments/assets/d0e9e4df-64f5-4dab-b926-27fb3292154f)
![Screenshot 2025-04-25 124636](https://github.com/user-attachments/assets/20d1f492-0672-477e-a370-dad152e0603e)
![Screenshot 2025-04-25 124653](https://github.com/user-attachments/assets/875c7e8a-3349-40e5-90ac-553e1475b53c)
![Screenshot 2025-04-25 124705](https://github.com/user-attachments/assets/29f2bedb-7b6c-4196-9f54-7d02af2c4044)


---

## 🛠️ Installation

```bash
git clone https://github.com/your-username/bilingual-question-similarity.git
cd bilingual-question-similarity

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -r requirements.txt

python app.py

