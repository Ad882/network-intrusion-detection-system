import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score
from sklearn.metrics import roc_curve
import plotly.graph_objects as go
import pickle
import streamlit as st
from utils import is_streamlit
import numpy as np
from typing import Tuple


def train_model() -> Tuple[pd.DataFrame, pd.Series, np.ndarray, RandomForestClassifier]:
    """
    Function: train_model

    Input:
        - None

    Output:
        - X_test: pd.DataFrame, Features of the test dataset.
        - y_test: pd.Series, True labels of the test dataset.
        - y_pred: np.ndarray, Predicted labels for the test dataset.
        - model: RandomForestClassifier, Trained model used for prediction.

    Description:
        Trains and test the NSL-KDD dataset with a RandomForestClassifier.
    """
    # PRE-PROCESSING
    train_data = pd.read_csv('nsl-kdd/KDDTrain+.txt', header=None)
    test_data = pd.read_csv('nsl-kdd/KDDTest+.txt', header=None)


    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
    ]
    train_data.columns = column_names
    test_data.columns = column_names

    train_data['label'] = train_data['label'].apply(lambda x: 0 if x == 'normal' else 1)
    test_data['label'] = test_data['label'].apply(lambda x: 0 if x == 'normal' else 1)

    categorical_columns = ['protocol_type', 'service', 'flag']
    encoders = {}
    for col in categorical_columns:
        encoder = LabelEncoder()
        train_data[col] = encoder.fit_transform(train_data[col])
        test_data[col] = encoder.transform(test_data[col])
        encoders[col] = encoder 

    with open('encoders/label_encoders.pkl', 'wb') as f:
        pickle.dump(encoders, f)


    columns_to_drop = [
        'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 
        'root_shell', 'su_attempted', 'num_root', 'num_file_creations', 
        'num_shells', 'num_access_files', 'num_outbound_cmds', 
        'is_host_login', 'is_guest_login', 'difficulty_level'
    ]

    train_data = train_data.drop(columns=columns_to_drop, axis=1)
    test_data = test_data.drop(columns=columns_to_drop, axis=1)


    # TRAINING
    print("Training...")
    X_train, X_test = train_data.drop(columns=['label'], axis=1), test_data.drop(columns=['label'], axis=1)
    y_train, y_test = train_data['label'], test_data['label']


    model = RandomForestClassifier(n_estimators=100, random_state=42, verbose=2)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    print("Training complete!")

    return X_test, y_test, y_pred, model


def evaluate_model(X_test: pd.DataFrame, y_test: pd.Series, y_pred: np.ndarray, model: RandomForestClassifier):
    """
    Function: evaluate_model

    Input:
        - X_test: pd.DataFrame, Features of the test dataset.
        - y_test: pd.Series, True labels of the test dataset.
        - y_pred: np.ndarray, Predicted labels for the test dataset.
        - model: RandomForestClassifier, Trained model used for prediction.

    Output:
        - None

    Description:
        Evaluates the performance of a trained model on the test dataset. It computes and displays
        the accuracy and F1-score of the model's predictions. Additionally, it plots the ROC curve based on the 
        predicted probabilities of the test data.

        In a Streamlit environment:
            - Displays the accuracy and F1-score using `st.write()`.
            - Plots the ROC curve using Plotly, which is displayed with `st.plotly_chart()`.

        In a standard environment:
            - Prints the accuracy and F1-score to the console.
            - Plots the ROC curve using Plotly and displays it via `fig.show()`.
    """
    if is_streamlit():
        st.write("Accuracy:", accuracy_score(y_test, y_pred))
        st.write("F1-score:", f1_score(y_test, y_pred))
        y_proba = model.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_proba)

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=fpr, y=tpr, mode='lines', name='ROC Curve'))

        fig.update_layout(
            title="ROC Curve",
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
            legend=dict(x=0.8, y=0.2)
        )

        st.plotly_chart(fig)
        
    else:
        print("Accuracy:", accuracy_score(y_test, y_pred))
        print("F1-score:", f1_score(y_test, y_pred))

        y_proba = model.predict_proba(X_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_proba)

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=fpr, y=tpr, mode='lines', name='ROC Curve'))

        fig.update_layout(
            title="ROC Curve",
            xaxis_title="False Positive Rate",
            yaxis_title="True Positive Rate",
            legend=dict(x=0.8, y=0.2)
        )
        
        fig.show()


def save_model(model: RandomForestClassifier):
    """
    Function: save_model

    Input:
        - model: RandomForestClassifier, The trained model to be saved.

    Output:
        - None

    Description:
        Saves a trained machine learning model to disk using the `pickle` library. The model is
        serialized and stored in a file named 'nsl-kdd_model.pkl' in the 'models' directory.
    """
    with open('models/nsl-kdd_model.pkl', 'wb') as file:
        pickle.dump(model, file)
