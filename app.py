import streamlit as st
import requests
import hashlib
import random
import string
from cryptography.fernet import Fernet
import time
import pandas as pd
import plotly.express as px
import io
from pyzbar.pyzbar import decode
import json
from PIL import Image
import re
from datetime import datetime
import qrcode

# Initialize session state
# Initialize session state
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'


# VirusTotal API key
VIRUSTOTAL_API_KEY = "3231a4122cc5300001ba8f4873dcc81cfefa8a5186b86e9e5be4ecf089825949"  # Replace with your actual API key

st.set_page_config(page_title="NetNinja Security Toolkit", page_icon="🛡️", layout="wide")

def scan_url_virustotal(url):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url}
    response = requests.post(api_url, data=data, headers=headers)
    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        time.sleep(20)  # Wait for analysis to complete
        return get_url_analysis_results(analysis_id)
    else:
        return "Error scanning URL"
# Custom CSS for improved appearance
st.markdown("""
<style>
    .reportview-container {
        background: linear-gradient(to right, #1E3A8A, #3B82F6);
    }
    .sidebar .sidebar-content {
        background-image: linear-gradient(#2e7bcf,#2e7bcf);
    }
    .Widget>label {
        color: white !important;
        font-family: 'Roboto', sans-serif;
    }
    .stTextInput>div>div>input, .stSelectbox>div>div>input, .stTextArea textarea {
        color: #4F8BF9;
        background-color: white;
        border-radius: 5px;
    }
    .big-font {
        font-size: 36px !important;
        font-weight: bold;
        color: white;
        font-family: 'Roboto', sans-serif;
        text-align: center;
        margin-bottom: 20px;
    }
    .medium-font {
        font-size: 24px !important;
        color: #E5E7EB;
        font-family: 'Roboto', sans-serif;
        text-align: center;
        margin-bottom: 30px;
    }
    .stButton>button {
        color: white;
        background-color: #4F8BF9;
        border-radius: 5px;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        color: #4F8BF9;
        background-color: white;
        box-shadow: 0 4px 6px rgba(50, 50, 93, 0.11), 0 1px 3px rgba(0, 0, 0, 0.08);
    }
    .tool-card {
        background-color: rgba(255, 255, 255, 0.1);
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }
    .tool-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 4px 6px rgba(50, 50, 93, 0.11), 0 1px 3px rgba(0, 0, 0, 0.08);
    }
    .tool-card h3 {
        color: white;
        font-family: 'Roboto', sans-serif;
        font-size: 24px;
        margin-bottom: 10px;
    }
    .tool-card p {
        color: #E5E7EB;
        font-family: 'Roboto', sans-serif;
        font-size: 16px;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions

# Ensure that get_url_analysis_results(

def get_url_analysis_results(analysis_id):
    api_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        result = response.json()
        stats = result['data']['attributes']['stats']
        return stats
    else:
        return "Error retrieving results"

def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, key):
    return Fernet(key).decrypt(encrypted_message.encode()).decode()

def calculate_file_hash(file_content):
    return hashlib.sha256(file_content).hexdigest()

def generate_password(length, use_letters=True, use_numbers=True, use_symbols=True):
    characters = ""
    if use_letters:
        characters += string.ascii_letters
    if use_numbers:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation
    
    return ''.join(random.choice(characters) for _ in range(length))



def encrypt_file(file_content, key):
    return Fernet(key).encrypt(file_content)

def decrypt_file(encrypted_content, key):
    return Fernet(key).decrypt(encrypted_content)

def upload_to_virustotal(file_content):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    files = {"file": file_content}
    response = requests.post(url, files=files, headers=headers)
    return response.json()

def create_and_download_graph(data, graph_type, title):
    if graph_type == "Bar Chart":
        fig = px.bar(data, x=data.index, y=data.values, title=title)
    elif graph_type == "Pie Chart":
        fig = px.pie(values=data.values, names=data.index, title=title)
    elif graph_type == "Line Chart":
        fig = px.line(x=data.index, y=data.values, title=title)
    
    buf = io.BytesIO()
    fig.write_image(buf, format="png")
    btn = st.download_button(
        label="Download Graph",
        data=buf.getvalue(),
        file_name=f"{title.lower().replace(' ', '_')}.png",
        mime="image/png"
    )
    
    return fig

def get_virustotal_report(analysis_id):
    url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()


def generate_qr_code(data):
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    return img_byte_arr.getvalue()

def analyze_password_strength(password):
    score = 0
    feedback = []

    if len(password) >= 12:
        score += 1
        feedback.append("Good length")
    else:
        feedback.append("Password should be at least 12 characters long")

    if re.search(r"\d", password):
        score += 1
        feedback.append("Contains numbers")
    else:
        feedback.append("Add numbers for stronger password")

    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
        feedback.append("Contains both uppercase and lowercase letters")
    else:
        feedback.append("Use both uppercase and lowercase letters")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
        feedback.append("Contains special characters")
    else:
        feedback.append("Add special characters for stronger password")

    return score, feedback

# Page functions
def home_page():
    st.markdown('<p class="big-font">Welcome to NetNinja</p>', unsafe_allow_html=True)
    st.markdown('<p class="medium-font">Your all-in-one security toolkit for the digital age. Protect, encrypt, and secure with ease.</p>', unsafe_allow_html=True)
    st.markdown("---")

    tools = [
        ("Phishing Link Scanner", "Scan URLs for potential phishing threats using VirusTotal's API."),
        ("Message Encrypter/Decrypter", "Encrypt and decrypt sensitive messages for secure communication."),
        ("File Integrity Checker", "Calculate and verify file hashes to ensure data integrity."),
        ("Password Generator", "Create strong, unique passwords to enhance your online security."),
        ("File Encrypter/Decrypter", "Secure your files with strong encryption and decrypt them when needed."),
        ("Password Strength Analyzer", "Analyze the strength of your passwords and get improvement suggestions."),
        ("QR Code Generator", "Generate QR codes for easy sharing of information."),
    ]

    cols = st.columns(3)
    for i, (tool_name, tool_description) in enumerate(tools):
        with cols[i % 3]:
            st.markdown(f"""
            <div class="tool-card">
                <h3>{tool_name}</h3>
                <p>{tool_description}</p>
            </div>
            """, unsafe_allow_html=True)
            if st.button(f"Go to {tool_name}", key=f"btn_{tool_name}"):
                st.session_state.current_page = tool_name
                st.rerun()

    st.markdown("---")
    st.markdown('<p class="medium-font">Select a tool from the cards above or use the sidebar to get started.</p>', unsafe_allow_html=True)

def phishing_link_scanner():
    st.header("Phishing Link Scanner")
    url = st.text_input("Enter URL to scan:")
    if st.button("Scan URL"):
        with st.spinner("Scanning URL..."):
            result = scan_url_virustotal(url)
            if isinstance(result, dict):
                st.write("Scan Results:")
                st.write(f"Malicious: {result['malicious']}")
                st.write(f"Suspicious: {result['suspicious']}")
                st.write(f"Harmless: {result['harmless']}")
                st.write(f"Undetected: {result['undetected']}")
                
                if result['malicious'] > 0:
                    st.error("⚠️ This URL was flagged as potentially malicious by one or more scanners.")
                elif result['suspicious'] > 0:
                    st.warning("⚠️ This URL was flagged as suspicious by one or more scanners.")
                else:
                    st.success("✅ No threats detected for this URL.")
                
            #     # Detailed analysis
            #     st.subheader("Detailed Analysis")
            #     analysis_id = result['id']
            #     detailed_result = get_url_analysis_results(analysis_id)
                
            #     if 'attributes' in detailed_result['data']:
            #         attributes = detailed_result['data']['attributes']
            #         st.write(f"Analysis date: {datetime.fromtimestamp(attributes['date'])}")
            #         st.write(f"Total engines: {attributes['total']}")
                    
            #         st.subheader("Engine Results")
            #         engine_results = attributes['results']
            #         for engine, data in engine_results.items():
            #             st.write(f"{engine}: {data['result'] or 'Clean'}")
                    
            #         # Analysis button and graph generation
            #         if st.button("Visualize Results"):
            #             st.subheader("Result Visualization")
            #             data = pd.DataFrame.from_dict(result, orient='index').reset_index()
            #             data.columns = ['Category', 'Count']
            #             fig = px.pie(data, values='Count', names='Category', title='URL Scan Results')
            #             st.plotly_chart(fig)
            #     else:
            #         st.error("Detailed analysis not available.")
            # else:
            #     st.error(f"Error: {result}")

def message_encrypter_decrypter():
    st.header("Message Encrypter/Decrypter")
    message = st.text_area("Enter message:")
    key = st.text_input("Enter encryption key (leave blank to generate a new one)")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Encrypt"):
            if not key:
                key = Fernet.generate_key().decode()
                st.session_state.message_key = key
                st.info(f"Generated key: {key}")
            encrypted = encrypt_message(message, key)
            st.success(f"Encrypted message: {encrypted}")
            
            # Generate QR code for encrypted message and key
            qr_data = json.dumps({"encrypted_message": encrypted, "key": key})
            qr = qrcode.QRCode(version=None, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_L)
            qr.add_data(qr_data)
            qr.make(fit=True)
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Convert PIL Image to bytes
            img_byte_arr = io.BytesIO()
            qr_image.save(img_byte_arr, format='PNG')
            qr_bytes = img_byte_arr.getvalue()
            
            st.image(qr_bytes, caption="QR Code for Encrypted Message and Key")
            st.download_button("Download QR Code", qr_bytes, "encrypted_message_qr.png", "image/png")

    with col2:
        if st.button("Decrypt"):
            if not key and 'message_key' in st.session_state:
                key = st.session_state.message_key
            try:
                decrypted = decrypt_message(message, key)
                st.success(f"Decrypted message: {decrypted}")
            except:
                st.error("Decryption failed. Make sure you're using the correct key.")

    st.markdown("---")
    st.subheader("Decrypt from QR Code")
    uploaded_qr = st.file_uploader("Upload QR Code image", type=['png', 'jpg', 'jpeg'])
    if uploaded_qr:
        qr_bytes = uploaded_qr.read()
        try:
            qr_image = Image.open(io.BytesIO(qr_bytes))
            decoded_objects = decode(qr_image)
            if decoded_objects:
                qr_data = json.loads(decoded_objects[0].data.decode('utf-8'))
                encrypted_message = qr_data['encrypted_message']
                qr_key = qr_data['key']
                decrypted = decrypt_message(encrypted_message, qr_key)
                st.success(f"Decrypted message from QR Code: {decrypted}")
            else:
                st.error("No QR code found in the image.")
        except json.JSONDecodeError:
            st.error("The QR code does not contain valid JSON data.")
        except KeyError:
            st.error("The QR code data is missing required fields (encrypted_message or key).")
        except Exception as e:
            st.error(f"An error occurred while processing the QR code: {str(e)}")

def file_integrity_checker():
    st.header("File Integrity Checker")
    uploaded_file = st.file_uploader("Choose a file")
    
    if uploaded_file:
        file_content = uploaded_file.read()
        calculated_hash = calculate_file_hash(file_content)
        st.success(f"Calculated SHA-256 hash: {calculated_hash}")
        
        st.markdown("---")
        st.subheader("Verify against known hash")
        provided_hash = st.text_input("Enter a known hash to verify against (optional):")
        if provided_hash:
            if provided_hash.lower() == calculated_hash.lower():
                st.success("✅ The provided hash matches the calculated hash. File integrity verified.")
            else:
                st.error("❌ The provided hash does not match the calculated hash. File may be corrupted or tampered with.")
        
        st.markdown("---")
        st.subheader("VirusTotal Scan")
        if st.button("Scan with VirusTotal"):
            with st.spinner("Uploading file to VirusTotal..."):
                upload_response = upload_to_virustotal(file_content)
                if "data" in upload_response:
                    analysis_id = upload_response["data"]["id"]
                    st.info("File uploaded successfully. Waiting for analysis...")
                    
                    time.sleep(30)
                    
                    report = get_virustotal_report(analysis_id)
                    if "data" in report:
                        stats = report["data"]["attributes"]["stats"]
                        st.write("Scan Results:")
                        st.write(f"Malicious: {stats['malicious']}")
                        st.write(f"Suspicious: {stats['suspicious']}")
                        st.write(f"Harmless: {stats['harmless']}")
                        st.write(f"Undetected: {stats['undetected']}")
                        
                        if stats['malicious'] > 0:
                            st.error("⚠️ The file was flagged as potentially malicious by one or more antivirus engines.")
                        elif stats['suspicious'] > 0:
                            st.warning("⚠️ The file was flagged as suspicious by one or more antivirus engines.")
                        else:
                            st.success("✅ No threats detected in the file.")
                        
                        # Analysis button and graph generation
                        if st.button("Analyze Results"):
                            st.subheader("Result Analysis")
                            data = pd.Series(stats)
                            graph_type = st.selectbox("Select Graph Type", ["Bar Chart", "Pie Chart", "Line Chart"])
                            fig = create_and_download_graph(data, graph_type, "File Scan Results")
                            st.plotly_chart(fig)
                    else:
                        st.error("Failed to retrieve the scan report. Please try again later.")
                else:
                    st.error("Failed to upload the file to VirusTotal. Please try again.")
        
        st.markdown("---")
        st.subheader("File Details")
        st.write(f"Filename: {uploaded_file.name}")
        st.write(f"File size: {len(file_content)} bytes")
        
        st.subheader("File Preview (first 100 bytes)")
        st.code(file_content[:100])



def password_generator():
    st.header("Password Generator")
    
    # User input for password generation
    length = st.slider("Password length", 8, 100000, 17)
    use_letters = st.checkbox("Use letters", value=True)
    use_numbers = st.checkbox("Use numbers", value=True)
    use_symbols = st.checkbox("Use symbols", value=True)
    
    # Generate password when button is clicked
    if st.button("Generate Password"):
        password = generate_password(length, use_letters, use_numbers, use_symbols)
        
        # Display the generated password directly in Markdown
        st.markdown(f"```\n{password}\n```")
        
        # Add info message
        st.write("Click to copy the password manually.")
        
    else:
        st.write("Click 'Generate Password' to create a password.")




# Main function call

def file_encrypter_decrypter():
    st.header("File Encrypter/Decrypter")
    file_to_process = st.file_uploader("Choose a file to encrypt/decrypt")
    file_key = st.text_input("Enter file encryption/decryption key (leave blank to generate a new one for encryption)")

    if file_to_process:
        file_content = file_to_process.read()
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Encrypt File"):
                if not file_key:
                    file_key = Fernet.generate_key().decode()
                    st.session_state.file_key = file_key
                    st.info(f"Generated key: {file_key}")
                encrypted_content = encrypt_file(file_content, file_key)
                st.download_button("Download Encrypted File", encrypted_content, "encrypted_file", "application/octet-stream")
        
        with col2:
            if st.button("Decrypt File"):
                if not file_key and 'file_key' in st.session_state:
                    file_key = st.session_state.file_key
                try:
                    decrypted_content = decrypt_file(file_content, file_key)
                    st.download_button("Download Decrypted File", decrypted_content, "decrypted_file", "application/octet-stream")
                except:
                    st.error("Decryption failed. Make sure you're using the correct key and that the file is encrypted.")


def password_strength_analyzer():
    st.header("Password Strength Analyzer")
    password = st.text_input("Enter a password to analyze:", type="password")
    if st.button("Analyze Password"):
        score, feedback = analyze_password_strength(password)
        st.write(f"Password Strength Score: {score}/4")
        for item in feedback:
            st.write(f"- {item}")
        
        if score == 4:
            st.success("Strong password!")
        elif score == 3:
            st.warning("Good password, but could be improved.")
        else:
            st.error("Weak password. Please consider the suggestions above.")

def qr_code_generator():
    st.header("QR Code Generator")
    data = st.text_input("Enter the data for the QR code:")
    if st.button("Generate QR Code"):
        qr_code = generate_qr_code(data)
        st.image(qr_code, caption="Generated QR Code")
        st.download_button("Download QR Code", qr_code, "qr_code.png", "image/png")

# Create a dictionary to store page functions
pages = {
    "Home": home_page,
    "Phishing Link Scanner": phishing_link_scanner,
    "Message Encrypter/Decrypter": message_encrypter_decrypter,
    "File Integrity Checker": file_integrity_checker,
    "Password Generator": password_generator,
    "File Encrypter/Decrypter": file_encrypter_decrypter,
    "Password Strength Analyzer": password_strength_analyzer,
    "QR Code Generator": qr_code_generator
}


# Sidebar
st.sidebar.title("NetNinja Tools")
st.sidebar.markdown("---")
for page in pages.keys():
    if st.sidebar.button(page):
        st.session_state.current_page = page
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.info("Choose a tool from the options above to get started.")

# To call the selected page function
if st.session_state.current_page in pages:
    pages[st.session_state.current_page]()
else:
    st.error("Page not found!")


        
