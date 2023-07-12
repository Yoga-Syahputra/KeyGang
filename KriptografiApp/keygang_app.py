from kivy.uix.screenmanager import ScreenManager, Screen
from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivy.uix.image import Image
from kivy.uix.widget import Widget
from kivy.uix.boxlayout import BoxLayout
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRectangleFlatButton, MDIconButton, MDFloatingActionButton, MDFlatButton
from kivy.core.window import Window
from kivy.uix.textinput import TextInput
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.metrics import dp
from pymongo import MongoClient
from datetime import datetime
import hashlib
import string

class KeyGang(MDApp):
    activity_history_screen = Screen(name='activity_history')

    def connect_to_database(self):
        # MongoDB Atlas Connection String
        client = MongoClient('mongodb+srv://keygang_db:wf2MwMVaB9MtZf9@keygang.fx2e0hf.mongodb.net/keygang_db?retryWrites=true&w=majority')
        # Database Name
        self.db = client['keygang_db']
        # Collection Name for Users
        self.collection = self.db['users']
        # Collection Name for Activity History
        self.activity_collection = self.db['activity_history']

    def build(self):

        self.screen_manager = ScreenManager()

        login_screen = Screen(name='login')
        self.create_login_screen(login_screen)
        self.screen_manager.add_widget(login_screen)

        welcome_screen = Screen(name='welcome')
        options_screen = Screen(name='options')
        help_screen = Screen(name='help')

        # Background
        background = Image(source='Background.png', allow_stretch=True, keep_ratio=False)

        # Layout for Image, Welcoming Text, dan Get Started-Related Button
        box_layout = MDBoxLayout(orientation='vertical', padding=[10, 50], spacing=10)

        # Logo
        image = Image(source='keygang.png', size_hint=(None, None), size=(400, 400))

        # Welcoming Text
        welcome_text = MDLabel(
            text="Welcome to KeyGang!",
            halign="center",
            theme_text_color="Custom",
            text_color=(0, 0, 1, 1),  # Blue color (R, G, B, A)
            font_style="H4",
            padding=[10, 0]
        )

        # Get Started Button -> Secure Your Password
        get_started_button = MDRectangleFlatButton(
            text="Secure Your Password",
            size_hint=(0.5, 0.1),
            pos_hint={'center_x': 0.5, 'center_y': 1.5},
            md_bg_color=(1, 1, 1, 1)  # Set the background color to white
        )
        get_started_button.bind(on_release=self.on_get_started)

        box_layout.add_widget(image)
        box_layout.add_widget(welcome_text)
        box_layout.add_widget(get_started_button)

        welcome_screen.add_widget(background)
        welcome_screen.add_widget(box_layout)

        self.screen_manager.add_widget(welcome_screen)
        self.screen_manager.add_widget(options_screen)
        self.screen_manager.add_widget(self.activity_history_screen)
        self.screen_manager.add_widget(help_screen)

        # Log Out Button
        logout_button = MDFloatingActionButton(
            icon="logout",
            size_hint=(None, None),  # Set size_hint to None
            size=("15dp", "15dp"),  # Set the desired size
            pos_hint={'center_x': 0.1, 'center_y': 0.1},
            on_release=self.on_logout
        )
        welcome_screen.add_widget(logout_button)

        return self.screen_manager

    def create_login_screen(self, screen):
        # Anchor Layout for Login Display
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center')

        # Background Image
        background_image = Image(source='Background.png', allow_stretch=True, keep_ratio=False)
        anchor_layout.add_widget(background_image)

        # Box Layout for Login
        box_layout = MDBoxLayout(orientation='vertical', padding=[10, 50], spacing=10)

        sign_in_label = MDLabel(
            text="SIGN INTO YOUR ACCOUNT",
            halign="center",
            theme_text_color="Custom",
            text_color=(0, 0, 1, 1),  # Blue color (R, G, B, A)
            font_style="H6",
            bold=True,
            padding=[10, 0]
        )

        # Label "Username"
        username_label = MDLabel(
            text="Username:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box Username
        username_text_box = TextInput(
            multiline=False,
            size_hint=(1, None),
            height='48dp'
        )

        # Label "Password"
        password_label = MDLabel(
            text="Password:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box Password
        password_text_box = TextInput(
            multiline=False,
            password=True,
            size_hint=(1, None),
            height='48dp'
        )

        # Login Button
        login_button = MDRectangleFlatButton(
            text="Login",
            size_hint=(1, None),
            height='48dp',
            md_bg_color=(1, 1, 1, 1)  # Set the background color to a specific value (e.g., RGB: 0.2, 0.4, 0.6)
        )
        login_button.bind(
            on_release=lambda instance: self.on_login(instance, username_text_box.text, password_text_box.text, screen))

        box_layout.add_widget(sign_in_label)
        box_layout.add_widget(username_label)
        box_layout.add_widget(username_text_box)
        box_layout.add_widget(password_label)
        box_layout.add_widget(password_text_box)
        box_layout.add_widget(login_button)

        anchor_layout.add_widget(box_layout)
        screen.add_widget(anchor_layout)

        # Label "Register"
        register_label = MDLabel(
            text="Don't have an account? Register:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box for Register Username
        self.register_username_text_box = TextInput(
            multiline=False,
            size_hint=(1, None),
            height='48dp'
        )

        # Text Box for Register Password
        self.register_password_text_box = TextInput(
            multiline=False,
            password=True,
            size_hint=(1, None),
            height='48dp'
        )

        # Register Button
        register_button = MDRectangleFlatButton(
            text="Register",
            size_hint=(1, None),
            height='48dp',
            md_bg_color=(1, 1, 1, 1)  # Set the background color to white (RGB: 1, 1, 1)
        )
        register_button.bind(on_release=self.on_register)

        # KeyGang! Copyright
        keygang_label = MDLabel(
            text="KeyGang! ©2023",
            halign="center",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),  # Set the text color to white (RGB: 1, 1, 1)
            font_style="Body2",
            padding=[10, 0]
        )

        box_layout.add_widget(register_label)
        box_layout.add_widget(self.register_username_text_box)
        box_layout.add_widget(self.register_password_text_box)
        box_layout.add_widget(register_button)
        box_layout.add_widget(keygang_label)

    def on_login(self, instance, username, password, screen):
        # Connect to the database
        self.connect_to_database()

        if not username or not password:
            self.show_warning("Input your username and password first!")
            return

        # Check Whether Username Exists in the Database
        query = {'username': username}
        existing_user = self.collection.find_one(query)

        if existing_user:
            # Hash the Entered Password for Comparison
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Check if the Hashed Password Matches the Stored Hashed Password
            if existing_user['password'] == hashed_password:
                # Set the current user for activity tracking
                self.current_user = existing_user['username']
                self.screen_manager.current = 'welcome'
            else:
                self.show_warning("Incorrect username or password!")
        else:
            self.show_warning("Incorrect username or password!")

    def on_register(self, instance):
        # Connect to the database
        self.connect_to_database()

        # Obtain Username and Password
        username = self.register_username_text_box.text
        password = self.register_password_text_box.text

        if not username or not password:
            self.show_warning("Input your username and password first!")
            return

        # Check whether username already exists in the database
        query = {'username': username}
        existing_user = self.collection.find_one(query)

        if existing_user:
            self.show_warning("This account already exists")
        else:
            # Hash the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            # Create a new user document
            user = {'username': username, 'password': hashed_password}

            # Insert the new user into the collection
            self.collection.insert_one(user)

            self.show_warning("Register Successful")
            self.screen_manager.current = 'login'

    def on_get_started(self, instance):
        self.screen_manager.current = 'options'
        self.create_options_screen()

    def on_logout(self, instance):
        content = BoxLayout(orientation='vertical', spacing=10, padding=[10, 10])

        # Confirmation Message
        label = Label(
            text="Are you sure you want to logout?",
            halign="center"
        )
        content.add_widget(label)

        # Confirmation Message
        button_box = BoxLayout(orientation='horizontal', spacing=10)

        # Yes Button
        yes_button = MDFlatButton(text="Yes")
        yes_button.bind(on_release=lambda instance: self.logout())
        button_box.add_widget(yes_button)

        # No Button
        no_button = MDFlatButton(text="No")
        no_button.bind(on_release=lambda instance: popup.dismiss())
        button_box.add_widget(no_button)

        content.add_widget(button_box)

        # Make Confirmation Popup
        popup = Popup(
            title="Confirmation",
            content=content,
            size_hint=(None, None),
            size=(400, 200)
        )
        popup.open()

    def logout(self):
        self.current_user = None
        self.screen_manager.current = self.screen_manager.previous()

    def create_options_screen(self):
        options_screen = self.screen_manager.get_screen('options')
        options_screen.clear_widgets()

        # Layout Box for Options and Encryption and Decryption
        box_layout = MDBoxLayout(orientation='vertical', padding=[10, 50], spacing=10)

        # Layout Box for Header (Arrow to Left and Title)
        header_layout = MDBoxLayout(orientation='horizontal', padding=[10, 0], spacing=10)

        # Back to Welcome Screen Button
        back_button = MDIconButton(
            icon='arrow-left',
            theme_text_color="Secondary",
            pos_hint={'center_x': 0.1, 'center_y': 0.5}
        )
        back_button.bind(on_release=self.on_back_from_options)

        # Options Screen Button
        options_label = MDLabel(
            text="Menu:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H5",
            padding=[10, 0]
        )

        # Spacer Widget
        spacer = Widget()

        # Layout Box ayout Box for Encryption and Decryption Button
        buttons_layout = MDBoxLayout(orientation='vertical', size_hint=(1, None), height='96dp', spacing=10)

        # Encryption Button
        encrypt_button = MDRectangleFlatButton(
            text="Encrypt",
            size_hint=(1, None),
            height='48dp'
        )
        encrypt_button.bind(on_release=self.on_encrypt)

        # Decryption Button
        decrypt_button = MDRectangleFlatButton(
            text="Decrypt",
            size_hint=(1, None),
            height='48dp'
        )
        decrypt_button.bind(on_release=self.on_decrypt)

        # Button for Activity History
        activity_history_button = MDRectangleFlatButton(
            text="Track History",
            size_hint=(1, None),
            height='48dp'
        )
        activity_history_button.bind(on_release=self.on_activity_history)

        # Help Button
        help_button = MDIconButton(
            icon='help-circle',
            theme_text_color="Secondary",
            pos_hint={'center_x': 0.9, 'center_y': 0.5}
        )
        help_button.bind(on_release=self.on_help)

        header_layout.add_widget(help_button)

        buttons_layout.add_widget(encrypt_button)
        buttons_layout.add_widget(decrypt_button)
        buttons_layout.add_widget(activity_history_button)

        header_layout.add_widget(back_button)
        header_layout.add_widget(options_label)

        box_layout.add_widget(header_layout)
        box_layout.add_widget(spacer)
        box_layout.add_widget(buttons_layout)

        options_screen.add_widget(box_layout)

    def on_encrypt(self, instance):
        input_screen = Screen(name='input')
        self.screen_manager.add_widget(input_screen)
        self.screen_manager.current = 'input'
        self.create_input_screen(input_screen, mode='encrypt')

    def on_decrypt(self, instance):
        input_screen = Screen(name='input')
        self.screen_manager.add_widget(input_screen)
        self.screen_manager.current = 'input'
        self.create_input_screen(input_screen, mode='decrypt')

    def create_help_screen(self):
        help_screen = self.screen_manager.get_screen('help')
        help_screen.clear_widgets()

        # How to Use
        help_text = MDLabel(
            text="HOW TO USE:\n\n1. Press the button Secure Your Password \n2. Choose one of these options; encrypt, decrypt, track history \n3. Good luck!",
            halign="center",
            theme_text_color="Secondary",
            font_style="Body1",
            padding=[10, 50]
        )

        # Back to Options Screen Button
        back_button = MDIconButton(
            icon='arrow-left',
            theme_text_color="Secondary",
            pos_hint={'center_x': 0.1, 'center_y': 0.5}
        )
        back_button.bind(on_release=self.on_back_from_help)

        help_screen.add_widget(help_text)
        help_screen.add_widget(back_button)

    def on_help(self, instance):
        self.screen_manager.current = 'help'
        self.create_help_screen()

    def create_input_screen(self, screen, mode):
        # Box Layout untuk Input dan Tombol Enkripsi/Dekripsi
        box_layout = MDBoxLayout(orientation='vertical', padding=[10, 50], spacing=10)

        # Label "Input"
        input_label = MDLabel(
            text="Input:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box Input
        input_text_box = TextInput(
            multiline=True,
            size_hint=(1, 1)
        )

        # Label "Key"
        key_label = MDLabel(
            text="Key:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box Key
        key_text_box = TextInput(
            multiline=False,
            size_hint=(1, None),
            height='48dp'
        )

        # Label "Output"
        result_label = MDLabel(
            text="Output:",
            halign="left",
            theme_text_color="Secondary",
            font_style="H6",
            padding=[10, 0]
        )

        # Text Box Output
        result_text_box = TextInput(
            multiline=True,
            size_hint=(1, 1)
        )

        # Encryption/Decryption Button
        action_button = MDRectangleFlatButton(
            text=mode.capitalize(),
            size_hint=(1, None),
            height='48dp'
        )
        action_button.bind(
            on_release=lambda instance: self.on_action(instance, input_text_box.text, key_text_box.text, mode,
                                                       result_text_box))

        # Back to Options Screen Button
        back_button = MDIconButton(
            icon='arrow-left',
            theme_text_color="Secondary",
            pos_hint={'center_x': 0.1, 'center_y': 0.5}
        )
        back_button.bind(on_release=self.on_back_from_input)

        box_layout.add_widget(back_button)
        box_layout.add_widget(input_label)
        box_layout.add_widget(input_text_box)
        box_layout.add_widget(key_label)
        box_layout.add_widget(key_text_box)
        box_layout.add_widget(result_label)
        box_layout.add_widget(result_text_box)
        box_layout.add_widget(action_button)

        screen.add_widget(box_layout)

    def on_action(self, instance, text, key, mode, result_text_box):
        if not key:
            self.show_warning("Key must be filled!")
            return

        if mode == 'encrypt':
            encrypted_text = self.vigenere_cipher_encrypt(text, key)
            result_text_box.text = encrypted_text
            self.save_to_history(text, key, encrypted_text, mode)
        elif mode == 'decrypt':
            decrypted_text = self.vigenere_cipher_decrypt(text, key)
            result_text_box.text = decrypted_text
            self.save_to_history(text, key, decrypted_text, mode)

    def save_to_history(self, input_text, key, output_text, mode):
        # Hash the plaintext, key, and ciphertext using SHA-256
        hashed_input = hashlib.sha256(input_text.encode()).hexdigest()
        hashed_key = hashlib.sha256(key.encode()).hexdigest()
        hashed_output = hashlib.sha256(output_text.encode()).hexdigest()

        # Get the Current Timestamp
        timestamp = datetime.now()

        # Create a Document for the Activity
        activity = {
            'timestamp': timestamp,
            'input_text': input_text,
            'hashed_input': hashed_input,
            'key': key,
            'hashed_key': hashed_key,
            'output_text': output_text,
            'hashed_output': hashed_output,
            'mode': mode
        }

        # Insert the Activity into the Activity History Collection
        self.activity_collection.insert_one(activity)

    def create_activity_history_screen(self):
        activities = self.activity_collection.find()

        if self.activity_history_screen.parent is None:
            self.screen_manager.add_widget(self.activity_history_screen)

        box_layout = MDBoxLayout(orientation='vertical', padding=[10, 50], spacing=10)

        title_label = MDLabel(
            text="Activity History:",
            halign="center",
            theme_text_color="Secondary",
            font_style="H5",
            padding=[10, 0]
        )

        scroll_view = ScrollView()

        scroll_content = MDBoxLayout(orientation='vertical', padding=[10, 0], spacing=10, size_hint_y=None)

        for activity in activities:
            timestamp = activity['timestamp'].strftime("%Y-%m-%d %H:%M:%S")
            input_text = activity['input_text']
            key = activity['key']
            output_text = activity['output_text']
            mode = activity['mode']

            # Censor the key
            censored_key = self.censor_text(key)

            activity_label = MDLabel(
                text=f"Timestamp: {timestamp}\nInput: {input_text}\nKey: {censored_key}\nOutput: {output_text}\nMode: {mode}",
                halign="left",
                theme_text_color="Secondary",
                font_style="Body1",
                padding=[10, 10],
                size_hint_y=None,
                height=dp(150)  # Adjust the Height of Each Activity Label as Needed
            )
            scroll_content.add_widget(activity_label)

        scroll_view.add_widget(scroll_content)

        back_button = MDIconButton(
            icon='arrow-left',
            theme_text_color="Secondary",
            pos_hint={'center_x': 0.1, 'center_y': 0.5}
        )
        back_button.bind(on_release=self.on_back_from_activity_history)

        box_layout.add_widget(back_button)
        box_layout.add_widget(title_label)
        box_layout.add_widget(scroll_view)

        self.activity_history_screen.clear_widgets()
        self.activity_history_screen.add_widget(box_layout)

    def on_activity_history(self, instance):
        self.screen_manager.current = 'activity_history'
        self.create_activity_history_screen()

    def on_back_from_options(self, instance):
        self.screen_manager.current = 'welcome'

    def on_back_from_input(self, instance):
        self.screen_manager.current = 'options'

    def on_back_from_activity_history(self, instance):
        self.screen_manager.current = 'options'

    def on_back_from_help(self, instance):
        self.screen_manager.current = 'options'

    def show_warning(self, text):
        content = BoxLayout(orientation='vertical', spacing=10, padding=[10, 10])

        # Warning Message
        label = Label(
            text=text,
            halign="center",
            color=(1, 1, 1, 1)  # Set text color to white (R,G,B,A)
        )
        content.add_widget(label)

        # OK Button
        ok_button = MDFlatButton(
            text="OK",
            theme_text_color="Custom",
            text_color=(1, 1, 1, 1),  # Set text color to white (R,G,B,A)
            size_hint=(None, None),
            size=(100, 50),
            pos_hint={'center_x': 0.5}  # Set the OK button position to the center
        )
        ok_button.bind(on_release=lambda instance: popup.dismiss())

        # Anchor Layout for OK Button
        anchor_layout = AnchorLayout(anchor_x='center', anchor_y='center')
        anchor_layout.add_widget(ok_button)
        content.add_widget(anchor_layout)

        # Make Notification Popup
        popup = Popup(
            title="Notification",
            content=content,
            size_hint=(None, None),
            size=(400, 200),
            background_color=(1, 1, 1, 1)
        )
        popup.open()

    def censor_text(self, text):
        # Censor the text by replacing each character with "*"
        censored_text = '*' * len(text)
        return censored_text

    def vigenere_cipher_encrypt(self, text, key):
        text = text.lower()
        key = key.lower()
        encrypted_text = ''

        for i in range(len(text)):
            char = text[i]
            if char.isalnum():
                char_set = string.ascii_lowercase + string.digits
                char_index = (char_set.index(char) + char_set.index(key[i % len(key)])) % len(char_set)
                encrypted_text += char_set[char_index]
            else:
                encrypted_text += char

        return encrypted_text

    def vigenere_cipher_decrypt(self, text, key):
        text = text.lower()
        key = key.lower()
        decrypted_text = ''

        for i in range(len(text)):
            char = text[i]
            if char.isalnum():
                char_set = string.ascii_lowercase + string.digits
                char_index = (char_set.index(char) - char_set.index(key[i % len(key)])) % len(char_set)
                decrypted_text += char_set[char_index]
            else:
                decrypted_text += char

        return decrypted_text

    def on_back_from_options(self, instance):
        self.screen_manager.current = 'welcome'

    def on_back_from_input(self, instance):
        self.screen_manager.current = 'options'
        input_screen = self.screen_manager.get_screen('input')
        self.screen_manager.remove_widget(input_screen)

    def on_back_from_help(self, instance):
        self.screen_manager.current = 'options'

if __name__ == '__main__':
    KeyGang().run()