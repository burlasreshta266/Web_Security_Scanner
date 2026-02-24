from fastapi import FastAPI
import sqlite3
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from scanner import Scanner
from fastapi.responses import HTMLResponse
import sqlite3

app = FastAPI()

orgins = [
    "http://localhost:5173"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=orgins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str


@app.get("/multi", response_class=HTMLResponse)
def multi_test(id: str = "", comment: str = ""):
    try:
        conn = sqlite3.connect("test.db")
        cursor = conn.cursor()

        # ❌ SQL Injection vulnerability
        query = f"SELECT * FROM users WHERE id = '{id}'"
        cursor.execute(query)
        data = cursor.fetchall()

    except Exception as e:
        # ❌ Leak SQL error to response
        return f"""
        <html>
            <body>
                <h2>Database Error:</h2>
                <p>{str(e)}</p>

                <!-- ❌ Sensitive Information Exposure -->
                <p>API_KEY = SECRET1234567890</p>

                <!-- ❌ Reflected XSS -->
                <div>User Comment: {comment}</div>
            </body>
        </html>
        """

    return {"data": data}

# http://127.0.0.1:8000/multi?id='&comment=<script>alert('XSS')</script>

@app.post("/scan")
def scan(request: ScanRequest):
    scanner = Scanner(request.url)
    scanner.scan()
    return {"vulnerabilities": scanner.vulnerabilities}