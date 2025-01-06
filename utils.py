from streamlit import runtime

def is_streamlit():
    return runtime.exists()