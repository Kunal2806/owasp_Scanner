import subprocess, json 
from fastapi import FastAPI, UploadFile, File

app = FastAPI()

@app.post("/scan/")
async def scan_file(file: UploadFile = File(...)):
     
    #Save upload File

    contents = await file.read()
    with open(file.filename, "wb") as f:
        f.write(contents)
    
    #Run Bandit scan

    result = subprocess.run(
        ["bandit", "-f", "json", "-r", file.filename],
        capture_output=True, text=True
    )

    findings = json.loads(result.stdout)
    return {"results": findings}