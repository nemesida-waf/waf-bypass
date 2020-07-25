import logging

def log_in(log,test_type, status_test):
    logging.basicConfig(filename="app.log", filemode = 'w', format=('%(message)s'), level=logging.INFO)
    log_message = '{} : {} in {}'.format(status_test,log,test_type)
    logging.info(log_message)
