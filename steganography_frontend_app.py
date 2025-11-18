# steganography_frontend_app.py
import streamlit as st
from PIL import Image
import io, base64
from cryptography.fernet import Fernet
from datetime import datetime

# import DB helpers
from database import init_db, create_user, verify_user, add_history, get_history, clear_history

# ensure DB initialized (safe to call)
init_db()

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="PixelWhisper", page_icon="🕶️", layout="wide")

# ---------------- SESSION STATE ----------------
if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "username" not in st.session_state:
    st.session_state.username = ""

# ---------------- THEME COLORS ----------------
def get_theme_colors():
    if st.session_state.theme == "dark":
        return {
            "bg": "#0e1117",
            "text": "#e0e0e0",
            "accent": "#00BCD4",
            "card_bg": "rgba(255,255,255,0.07)",
            "sidebar_bg": "#111",
            "sidebar_text": "#ddd"
        }
    else:
        return {
            "bg": "#f5f5f5",
            "text": "#222",
            "accent": "#0078D7",
            "card_bg": "#ffffff",
            "sidebar_bg": "#e6e6e6",
            "sidebar_text": "#333"
        }

colors = get_theme_colors()

# ---------------- CUSTOM CSS ----------------
st.markdown(f"""
<style>
body {{
    background-color: {colors["bg"]};
    color: {colors["text"]};
}}
div[data-testid="stSidebar"] {{
    background-color: {colors["sidebar_bg"]} !important;
    color: {colors["sidebar_text"]};
}}
h1,h2,h3,h4,p,label {{
    color: {colors["text"]} !important;
}}
.stButton>button {{
    background-color: {colors["accent"]};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 600;
}}
.center-card {{
  max-width: 520px;
  margin: 30px auto;
  background: {colors['card_bg']};
  padding: 22px;
  border-radius: 12px;
  box-shadow: 0 6px 22px rgba(0,0,0,0.35);
}}
.stat-card {{
    background-color: {colors["card_bg"]};
    border-radius: 10px;
    padding: 12px 20px;
    text-align: center;
    font-size: 1rem;
    margin: 5px;
}}
</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ----------------
st.markdown(f"""
<div style='text-align:center;margin-top:30px;'>
    <img src="https://cdn-icons-png.flaticon.com/512/942/942751.png" width="70">
    <h1 style="color:{colors['accent']};margin-bottom:5px;">🕶️ PixelWhisper</h1>
    <p style="font-size:17px;color:{colors['text']};">Hide Secrets in Plain Sight</p>
</div>
""", unsafe_allow_html=True)

# ---------------- AUTH CARD (FULL PROTECTION) ----------------
def show_auth_card():
    st.markdown("<div class='center-card'>", unsafe_allow_html=True)
    st.markdown("## 🔐 PixelWhisper — Login / Register", unsafe_allow_html=True)

    tab = st.radio("", ["Login", "Register"], horizontal=True)

    if tab == "Login":
        with st.form("login_form"):
            uname = st.text_input("Username", key="login_uname")
            pwd = st.text_input("Password", type="password", key="login_pwd")
            submitted = st.form_submit_button("Login")
            if submitted:
                ok, user_id, msg = verify_user(uname, pwd)
                if ok:
                    st.success(msg)
                    st.session_state.logged_in = True
                    st.session_state.user_id = user_id
                    st.session_state.username = uname.strip().lower()
                    # reload app to show main UI
                    st.rerun()
                else:
                    st.error(msg)
    else:
        with st.form("register_form"):
            r_uname = st.text_input("Choose a username", key="reg_uname")
            r_pwd = st.text_input("Choose a password (min 4 chars)", type="password", key="reg_pwd")
            r_pwd2 = st.text_input("Confirm password", type="password", key="reg_pwd2")
            submitted = st.form_submit_button("Register")
            if submitted:
                if r_pwd != r_pwd2:
                    st.error("Passwords do not match.")
                else:
                    ok, msg = create_user(r_uname, r_pwd)
                    if ok:
                        st.success(msg + " You can now login.")
                    else:
                        st.error(msg)

    st.markdown("</div>", unsafe_allow_html=True)

# If not logged in, require login
if not st.session_state.logged_in:
    st.info("This app is protected. Please log in or register to continue.")
    show_auth_card()
    st.stop()

# ---------------- SIDEBAR (post-login) ----------------
st.sidebar.markdown(f"**Logged in as:**  {st.session_state.username}")
if st.sidebar.button("Logout"):
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = ""
    st.experimental_rerun()

st.sidebar.title("📂 Navigation")
selected_page = st.sidebar.radio("Go to", ["🏠 About", "💡 How to Use", "🧩 Encode", "🔍 Decode", "📜 History"])

# ---------------- ENCRYPTION HELPERS ----------------
_DELIM = "<<!END!>>"

def encrypt_message(message, password):
    key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    token = Fernet(key).encrypt(message.encode())
    return base64.b64encode(token).decode()

def decrypt_message(encrypted_b64, password):
    key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    token = base64.b64decode(encrypted_b64)
    return Fernet(key).decrypt(token).decode()

# ---------------- STEGANOGRAPHY ----------------
def encode_message(img, message):
    full_message = message + _DELIM
    binary_message = ''.join(format(ord(c), '08b') for c in full_message)
    encoded = img.copy()
    pixels = encoded.load()
    width, height = img.size
    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])
            for i in range(3):
                if data_index < len(binary_message):
                    pixel[i] = (pixel[i] & ~1) | int(binary_message[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)
            if data_index >= len(binary_message):
                return encoded
    return encoded

def decode_message(img):
    binary_data = ''.join(str(color & 1) for pixel in list(img.getdata()) for color in pixel[:3])
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded = ''
    for byte in all_bytes:
        if len(byte) < 8:
            continue
        decoded += chr(int(byte, 2))
        if decoded.endswith(_DELIM):
            return decoded[:-len(_DELIM)]
    return decoded

# ---------------- STATS (user-specific) ----------------
hist_rows = get_history(st.session_state.user_id, limit=500)
encodes = sum(1 for r in hist_rows if "Encoded" in r[0] or "🔒" in r[0])
decodes = sum(1 for r in hist_rows if "Decoded" in r[0] or "🔍" in r[0])

cols = st.columns(3)
cols[0].markdown(f"<div class='stat-card'>🧩 Encoded: <b>{encodes}</b></div>", unsafe_allow_html=True)
cols[1].markdown(f"<div class='stat-card'>🔍 Decoded: <b>{decodes}</b></div>", unsafe_allow_html=True)
cols[2].markdown(f"<div class='stat-card'>📜 History Entries: <b>{len(hist_rows)}</b></div>", unsafe_allow_html=True)

# ---------------- PAGES ----------------
# 🏠 ABOUT
if selected_page == "🏠 About":
    st.subheader("About the App")
    st.markdown(f"""
    **PixelWhisper** is a secure steganography-based tool that lets you **hide secret text messages inside images**.  
    It merges **cryptography and steganography** to make your data invisible yet safe.  

    ### 🔐 Key Highlights
    - **Dual Protection:** Encrypts your message using your chosen password.  
    - **Invisible Encoding:** Pixel values are subtly modified — no visible difference to the human eye.  
    - **Privacy First:** Your data never leaves your device.  
    - **History Tracking:** View your recent encoding and decoding activities.  
    - **Simple UI:** Clean and modern design for easy use.  

    PixelWhisper — *because even pixels can keep secrets.* 🕶️
    """)

# 💡 HOW TO USE
elif selected_page == "💡 How to Use":
    st.subheader("💡 How to Use PixelWhisper")
    st.markdown("""
    ### 🧩 Encoding a Message
    1️⃣ Go to **Encode** from the sidebar.  
    2️⃣ Upload a cover image (PNG or JPG).  
    3️⃣ Type the secret message you want to hide.  
    4️⃣ Optionally, set a password for encryption.  
    5️⃣ Click **Encode 🔒** and download the encoded image.  

    ### 🔍 Decoding a Message
    1️⃣ Open **Decode** from the sidebar.  
    2️⃣ Upload the encoded image.  
    3️⃣ If you used a password, enter it.  
    4️⃣ Click **Decode 🧩** to reveal the hidden message.  

    ### 🕒 Viewing History
    - Go to the **History** tab to see your personal encoding and decoding activities.  
    - Use Clear History to remove your personal history.
    """)

# 🧩 ENCODE
elif selected_page == "🧩 Encode":
    st.subheader("🧩 Encode a Secret Message")
    uploaded_image = st.file_uploader("Upload image", type=["png", "jpg", "jpeg"])
    secret_message = st.text_area("Enter your secret message")
    password = st.text_input("Set a password (optional)", type="password")

    if st.button("Encode 🔒"):
        if uploaded_image and secret_message:
            img = Image.open(uploaded_image).convert("RGB")
            if password:
                secret_message = encrypt_message(secret_message, password)
            encoded_img = encode_message(img, secret_message)
            buf = io.BytesIO()
            encoded_img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode()
            st.success("✅ Message successfully encoded!")
            st.markdown(f'<a href="data:file/png;base64,{b64}" download="encoded_image.png">📥 Download Encoded Image</a>', unsafe_allow_html=True)

            # save per-user history
            add_history(st.session_state.user_id, "Encoded", getattr(uploaded_image, "name", "uploaded_image"))
        else:
            st.error("Please upload an image and enter a message.")

# 🔍 DECODE
elif selected_page == "🔍 Decode":
    st.subheader("🔍 Decode Message")
    uploaded2 = st.file_uploader("Upload encoded image", type=["png", "jpg", "jpeg"])
    password2 = st.text_input("Password (if required)", type="password")

    if st.button("Decode 🧩"):
        if uploaded2:
            img = Image.open(uploaded2).convert("RGB")
            decoded_text = decode_message(img)
            try:
                if password2:
                    decoded_text = decrypt_message(decoded_text, password2)
                    st.success("✅ Hidden Message Found (decrypted):")
                else:
                    st.success("✅ Hidden Message Found:")
                st.code(decoded_text)

                # save per-user history
                add_history(st.session_state.user_id, "Decoded", getattr(uploaded2, "name", "uploaded_image"))

            except Exception as e:
                st.error("Incorrect password or corrupted data.")
        else:
            st.error("Please upload an encoded image.")

# 📜 HISTORY
elif selected_page == "📜 History":
    st.subheader("📜 Your Activity (saved permanently)")
    rows = get_history(st.session_state.user_id, limit=500)

    if rows:
        if st.button("🗑 Clear History"):
            clear_history(st.session_state.user_id)
            st.success("History cleared.")
        st.markdown("### Activity Log (most recent first)")
        for action, filename, ts in rows:
            st.markdown(f"<div style='background:{colors['card_bg']};padding:8px;border-radius:8px;margin-bottom:6px;'><b>{action}</b> — {filename}<div style='opacity:0.7;font-size:12px;margin-top:6px;'>{ts}</div></div>", unsafe_allow_html=True)
    else:
        st.info("No recent activity yet. Your actions will appear here.")

# ---------------- FOOTER ----------------
st.markdown(f"""
<hr style="opacity:0.2;">
<p style="text-align:center;opacity:0.7;font-size:14px;">
🕶️ <b>PixelWhisper © 2025</b> | Secure Data Hiding by <b>Aslesha Parida</b>
</p>
""", unsafe_allow_html=True)
