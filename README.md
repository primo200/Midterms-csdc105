# Midterms-csdc105

##How to Run the Project

Follow these steps to run the application on your local machine:

### Prerequisites

- Python 3.8 or higher installed
- Git installed
- Internet connection (for Supabase database access)

Step-by-Step Setup

**Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   cd YOUR_REPO_NAME

**Create and activate a virtual environment**

 ```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
  
**Create a .env file in the root directory**
  DATABASE_URL=postgresql://postgres.fjhmljrnuezbmsoylhcc:chatgptdabest@aws-1-ap-southeast-1.pooler.supabase.com:6543/postgres?  sslmode=require
SECRET_KEY=your-secret-key-here

**Run the application**
    ```bash
python app.py

**Open your browser and navigate to: http://127.0.0.1:5000**
