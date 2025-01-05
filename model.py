import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.metrics import roc_auc_score, roc_curve
import matplotlib.pyplot as plt
import pickle


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
for col in categorical_columns:
    encoder = LabelEncoder()
    train_data[col] = encoder.fit_transform(train_data[col])
    test_data[col] = encoder.fit_transform(test_data[col])



# TRAINING
print("Training...")
X_train, X_test = train_data.drop('label', axis=1), test_data.drop('label', axis=1)
y_train, y_test = train_data['label'], test_data['label']


model = RandomForestClassifier(n_estimators=100, random_state=42, verbose=2)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("Training complete!")



def evaluate_model(X_test, y_test, y_pred):
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

    y_proba = model.predict_proba(X_test)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, y_proba)

    plt.figure(figsize=(10, 6))
    plt.plot(fpr, tpr)
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("ROC Curve")
    plt.show()


def save_model(model):
    with open('models/nsl-kdd_model.pkl', 'wb') as file:
        pickle.dump(model, file)




evaluate_model(X_test, y_test, y_pred)
save_model(model)