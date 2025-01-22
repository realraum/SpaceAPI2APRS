import logging


def setup_custom_logger(name='root', stdout_level=logging.DEBUG):
    logger = logging.getLogger(name)
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - [%(module)s] %(message)s')
    logger.setLevel(logging.DEBUG)

    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(stdout_level)
    stdout_handler.setFormatter(formatter)

    # logger.setLevel(stdout_level)
    logger.addHandler(stdout_handler)
    return logger