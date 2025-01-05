import pandas as pd
from sklearn.preprocessing import LabelEncoder
import pickle
import plotly.express as px
import plotly.graph_objects as go


def preprocessing(capture_file):
    data = pd.read_csv(capture_file)

    categorical_columns = ['protocol_type', 'service', 'flag']
    for col in categorical_columns:
        encoder = LabelEncoder()
        data[col] = encoder.fit_transform(data[col])

    return data


def find_outliers(data, model_file, feature):
    with open(model_file, 'rb') as file:
        model = pickle.load(file)

    data['label'] = model.predict(data)

    outliers = data[data['label'] == 1]
    detected_outliers = len(outliers)
    non_outliers = len(data) - len(outliers)
    print(f"Number of detected outliers: {detected_outliers}")
    print(f"Number of detected non outliers: {non_outliers}")

    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=data.index,
        y=data[feature],
        mode='markers',
        marker=dict(color='blue', size=6, opacity=0.6),
        name='Normal'
    ))

    fig.add_trace(go.Scatter(
        x=outliers.index,
        y=outliers[feature],
        mode='markers',
        marker=dict(color='red', size=8, line=dict(width=1, color='black')),
        name='Outliers'
    ))

    fig.update_layout(
        title=f'Visualization of Detected Outliers ({feature})',
        xaxis_title='Index',
        yaxis_title=feature,
        legend=dict(yanchor="top", y=0.99, xanchor="left", x=0.01),
        template='plotly_white'
    )

    fig.show()