import pandas as pd
import json
import re
import sys
from typing import Dict, Any, Tuple

# regex patterns are here ...... no need to add email 
phoneRegex = re.compile(r'\b\d{10}\b')
aadharRegex = re.compile(r'\b\d{12}\b|\b\d{4}\s\d{4}\s\d{4}\b')
passportRegex = re.compile(r'\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b|\b[A-PR-WYa-pr-wy]\d{7}\b')
upiRegex = re.compile(r'[\w.-]+@[\w.-]+')

standalonePiiFields = {
    "phone": phoneRegex,
    "contact": phoneRegex,
    "aadhar": aadharRegex,
    "passport": passportRegex,
    "upi_id": upiRegex,
}

combinatorialPiiFields = [
    "name",
    "email",
    "address",
    "ip_address",
    "device_id"
]

def redactPhone(phoneNum: str) -> str:
    return f"{phoneNum[:2]}XXXXXX{phoneNum[-2:]}"

def redactAadhar(aadharNum: str) -> str:
    aadharDigits = aadharNum.replace(" ", "")
    return f"XXXXXXXX{aadharDigits[-4:]}"

def redactPassport(passportNum: str) -> str:
    return f"{passportNum[0]}XXXXXX{passportNum[-1]}"

def redactUpi(upiId: str) -> str:
    parts = upiId.split('@')
    if len(parts) == 2:
        user, domain = parts
        return f"{user[:2]}XXXX@{domain}"
    return "XXXX@XXXX"

def redactName(name: str) -> str:
    parts = name.split()
    if len(parts) > 1:
        return f"{parts[0][0]}XXX {parts[-1][0]}XXX"
    return f"{name[0]}XXX"

def redactEmail(email: str) -> str:
    parts = email.split('@')
    if len(parts) == 2:
        user, domain = parts
        return f"{user[:2]}XXX@{domain}"
    return "XXX@XXXX.com"

def redactGeneric(value: Any) -> str:
    return "[REDACTED_PII]"

redactionFunctions = {
    "phone": redactPhone,
    "contact": redactPhone,
    "aadhar": redactAadhar,
    "passport": redactPassport,
    "upi_id": redactUpi,
    "name": redactName,
    "email": redactEmail,
    "address": redactGeneric,
    "ip_address": redactGeneric,
    "device_id": redactGeneric,
}

def processRecord(data: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    redactedData = data.copy()
    piiFound = False
    piiFieldsInRecord = set()

    for key, value in data.items():
        if isinstance(value, str):
            if key in standalonePiiFields and standalonePiiFields[key].search(value):
                piiFound = True
                piiFieldsInRecord.add(key)

    combinatorialCount = 0
    combinatorialKeys = []
    for key in combinatorialPiiFields:
        if key in data and data[key]:
            if key == 'name' and len(str(data[key]).split()) < 2:
                continue
            combinatorialCount += 1
            combinatorialKeys.append(key)

    if combinatorialCount >= 2:
        piiFound = True
        for key in combinatorialKeys:
            piiFieldsInRecord.add(key)

    if piiFound:
        for key in piiFieldsInRecord:
            if key in redactedData and key in redactionFunctions:
                originalValue = str(redactedData[key])
                redactedData[key] = redactionFunctions[key](originalValue)

    return redactedData, piiFound

def main(inputFile: str):
    try:
        df = pd.read_csv(inputFile)
    except FileNotFoundError:
        print(f"file not found '{inputFile}'")
        sys.exit(1)

    results = []

    for index, row in df.iterrows():
        recordId = row['record_id']
        try:
            dataJsonStr = row['data_json']
            if isinstance(dataJsonStr, str):
                dataJsonStr = dataJsonStr.replace('""', '"')
            data = json.loads(dataJsonStr)
        except (json.JSONDecodeError, TypeError):
            results.append({
                'record_id': recordId,
                'redacted_data_json': json.dumps({"error": "Invalid JSON format"}),
                'is_pii': False
            })
            continue

        redactedData, isPii = processRecord(data)

        results.append({
            'record_id': recordId,
            'redacted_data_json': json.dumps(redactedData),
            'is_pii': isPii
        })

    outputDf = pd.DataFrame(results)
    outputFile = 'redacted_output_candidate_full_name.csv'
    outputDf.to_csv(outputFile, index=False)
    print(f"saved the file '{outputFile}'")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)

    inputFile = sys.argv[1]
    main(inputFile)
