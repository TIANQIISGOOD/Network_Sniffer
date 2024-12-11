from ui.main_interface import MainInterface
from utils.logger import logger

if __name__ == "__main__":
    try:
        logger.info("启动网络嗅探器...")
        app = MainInterface()
        app.run()
    except Exception as e:
        logger.error(f"程序运行异常: {e}")
