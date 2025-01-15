from streamlit import runtime
import grp
import os
import sys
import pwd
from collections import deque
import streamlit as st
from utils import is_streamlit

connections = deque(maxlen=1000)


def is_streamlit():
    return runtime.exists()


def check_permissions():
    try:
        user_id = os.getuid()
        user_name = pwd.getpwuid(user_id).pw_name
        groups = [g.gr_name for g in grp.getgrall() if user_name in g.gr_mem]
        
        if 'wireshark' in groups:
            if is_streamlit():
                st.success("✅ The user has the necessary permissions to capture packets.")
            else:
                print("The user has the necessary permissions to capture packets.\n---")
        else:
            if is_streamlit():
                st.error("🚨 The user does not have the necessary permissions. Please add the user to the 'wireshark' group.")
            else:
                print("The user does not have the necessary permissions. Please add the user to the 'wireshark' group.")
            sys.exit(1)
    
    except Exception as e:
        if is_streamlit():
            st.error(f"Error checking permissions: {e}")
        else:
            print(f"Error checking permissions: {e}")
        sys.exit(1)