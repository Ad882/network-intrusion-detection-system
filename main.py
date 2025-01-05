from model import train_model, evaluate_model, save_model 
from capture import check_permissions, capture_traffic, live_capture_traffic
from analysis import preprocessing, find_outliers

if __name__ == "__main__":
    model_training = input(f"Should the model be re-trained? (y/n)")
    if model_training.lower() == "y":
        X_test, y_test, y_pred, model = train_model()
        save_model(model)

        model_perf = input(f"Should the model performances be shown? (y/n)")
        if model_perf.lower() == "y":
            evaluate_model(X_test, y_test, y_pred, model)


    real_time_capture = input(f"Do you want to operate in real time? (y/n)")
    capture_file = 'capture/network_traffic.csv'
    model_file = 'models/nsl-kdd_model.pkl'
    interface='wlp1s0'

    if real_time_capture.lower() == "y":
        live_capture_traffic(interface, model_file)
    else:
        perform_capture = input(f"Should a network capture be made? (y/n)")
        if perform_capture.lower() == "y":
            while True:
                try:
                    capture_duration = int(input(f"Which duration (in seconds)? "))
                    if capture_duration > 0:
                        break
                    else:
                        print("Duration must be a positive number.")
                except ValueError:
                    print("Please enter a valid integer.")

            check_permissions()
            capture_traffic(interface, capture_file, capture_duration)

        print("Checking for outliers...")
        data = preprocessing(capture_file)
        find_outliers(data, model_file, feature='flag')
        print("Watch the plot on the browser!")