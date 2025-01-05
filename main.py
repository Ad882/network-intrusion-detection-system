from model import train_model, evaluate_model, save_model 
from capture import check_permissions, capture_traffic
from analysis import preprocessing, find_outliers

if __name__ == "__main__":
    model_training = input(f"Should the model be re-trained? (y/n)")
    if model_training.lower() == "y":
        X_test, y_test, y_pred, model = train_model()
        save_model(model)

        model_perf = input(f"Should the model performances be shown? (y/n)")
        if model_perf.lower() == "y":
            evaluate_model(X_test, y_test, y_pred, model)


    perform_capture = input(f"Should a network capture be made? (y/n)")
    if perform_capture.lower() == "y":
        check_permissions()
        capture_traffic(interface='wlp1s0', output_file='capture/network_traffic.csv', capture_duration=30)

    capture_file = 'capture/network_traffic.csv'
    model = 'models/nsl-kdd_model.pkl'

    print("Checking for outliers...")
    data = preprocessing(capture_file)
    find_outliers(data, model, feature='flag')
    print("Watch the plot on the browser!")