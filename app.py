import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from nids_model import train_model

st.set_page_config(page_title="NIDS Dashboard", layout="wide")

st.title("🔐 Network Intrusion Detection System")
st.markdown("### Machine Learning based Cyber Attack Detection Dashboard")

model, scaler, acc, cm = train_model()

col1, col2, col3 = st.columns(3)
col1.metric("Model Accuracy", f"{acc*100:.2f}%")
col2.metric("Algorithm", "Random Forest")
col3.metric("Status", "Active")

st.markdown("---")

st.subheader("📊 Confusion Matrix")
fig, ax = plt.subplots()
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax)
st.pyplot(fig)

st.markdown("---")

st.subheader("📂 Upload Network Traffic for Prediction")
uploaded_file = st.file_uploader("Upload CSV file (without label column)", type=["csv"])

if uploaded_file:
    test_data = pd.read_csv(uploaded_file)
    st.write("Preview", test_data.head())

    scaled = scaler.transform(test_data)
    preds = model.predict(scaled)

    test_data["Prediction"] = np.where(preds == 1, "Attack", "Normal")

    st.subheader("🔍 Detection Results")
    st.dataframe(test_data, use_container_width=True)

    attack_count = (test_data["Prediction"] == "Attack").sum()
    normal_count = (test_data["Prediction"] == "Normal").sum()

    st.markdown("### 🚦 Traffic Distribution")
    fig2, ax2 = plt.subplots()
    ax2.bar(["Attack", "Normal"], [attack_count, normal_count])
    st.pyplot(fig2)

st.markdown("---")

st.subheader("📘 Model Information")
st.write("This system classifies network traffic using supervised machine learning and identifies potential cyber threats.")
st.write("Trained on public intrusion detection datasets (NSL-KDD / CICIDS).")
