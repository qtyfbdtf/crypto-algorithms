import customtkinter as ctk
from tkinter import messagebox
from algorithms import AlgorithmSelector
from config import ALGORITHM_METADATA


class AlgorithmApp(ctk.CTk):
    def __init__(self, algorithm_selector):
        super().__init__()
        self.algorithm_selector = algorithm_selector
        self.open_popups = []
        self.title("Encryption Algorithm Selector")
        self.geometry("600x550")
        self.algorithms = ALGORITHM_METADATA
        self.create_widgets()

    def create_widgets(self):
        # Dropdown menu for algorithm selection
        self.label_algorithm = ctk.CTkLabel(self, text="Select Algorithm:")
        self.label_algorithm.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.selected_algorithm = ctk.StringVar(value="Caesar Cipher")
        self.dropdown = ctk.CTkOptionMenu(
            self,
            variable=self.selected_algorithm,
            values=list(self.algorithms.keys()),
            command=self.update_key_input
        )
        self.dropdown.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Text area for message input
        self.label_message = ctk.CTkLabel(self, text="Enter Message:")
        self.label_message.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.entry_message = ctk.CTkEntry(self, width=400)
        self.entry_message.grid(row=1, column=1, padx=10, pady=10)

        # Key input field
        self.label_key = ctk.CTkLabel(self, text="Enter Key:")
        self.label_key.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.entry_key = ctk.CTkEntry(self, width=400)
        self.entry_key.grid(row=2, column=1, padx=10, pady=10)

        # Checkbox for special characters
        self.include_special_chars = ctk.BooleanVar(value=False)
        self.checkbox_special_chars = ctk.CTkCheckBox(
            self, text="Include Special Characters", variable=self.include_special_chars
        )
        self.checkbox_special_chars.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        # Generated key display
        self.label_generated_key = ctk.CTkLabel(self, text="Generated Key:")
        self.label_generated_key.grid(row=4, column=0, padx=10, pady=10, sticky="w")

        self.generated_key_output = ctk.CTkTextbox(self, width=400, height=30)
        self.generated_key_output.grid(row=4, column=1, padx=10, pady=10)
        self.generated_key_output.bind("<Key>", lambda e: "break")  # Read-only

        # Result display
        self.label_result = ctk.CTkLabel(self, text="Result:")
        self.label_result.grid(row=5, column=0, padx=10, pady=10, sticky="w")

        self.result_output = ctk.CTkTextbox(self, width=400, height=100)
        self.result_output.grid(row=5, column=1, padx=10, pady=10)
        self.result_output.bind("<Key>", lambda e: "break")  # Read-only

        # Encrypt button
        self.button_encrypt = ctk.CTkButton(
            self,
            text="Encrypt",
            command=self.run_algorithm
        )
        self.button_encrypt.grid(row=6, column=1, padx=10, pady=20, sticky="e")

        self.update_key_input("Caesar Cipher")

    def update_key_input(self, algorithm):
        algorithm_data = self.algorithms[algorithm]

        # Manage key input field visibility
        key_type_none = algorithm_data["key_type"] == "none"
        self.toggle_widget(self.label_key, not key_type_none)
        self.toggle_widget(self.entry_key, not key_type_none)
        if not key_type_none:
            self.label_key.configure(text=f"Enter {algorithm_data['key_label']}:")

        # Toggle special characters checkbox
        self.toggle_widget(self.checkbox_special_chars, algorithm in ["Vigenere Cipher", "Caesar Cipher"])

        # Manage generated key visibility
        generated_key = algorithm_data.get("generated_key", False)
        self.toggle_widget(self.label_generated_key, generated_key)
        self.toggle_widget(self.generated_key_output, generated_key)

    def toggle_widget(self, widget, show):
        """ Method to show or hide widgets based on the 'show' flag."""
        widget.grid() if show else widget.grid_remove()

    def run_algorithm(self):
        try:
            # Close all open popups before starting a new encryption
            self.close_all_popups()

            algorithm = self.selected_algorithm.get()
            message = self.entry_message.get()
            key = self.entry_key.get()

            if not message:
                messagebox.showerror("Error", "Message cannot be empty!")
                return

            # Validate the key type based on the selected algorithm
            if self.algorithms[algorithm]["key_type"] == "int":
                try:
                    key = int(key)  # Convert the key to an integer for Caesar Cipher
                except ValueError:
                    messagebox.showerror("Error", "Key must be an integer!")
                    return

            elif self.algorithms[algorithm]["key_type"] == "str" and not key:
                messagebox.showerror("Error", "Key cannot be empty!")
                return

            include_special_chars = (
                self.include_special_chars.get() if algorithm in ["Vigenere Cipher", "Caesar Cipher"] else None
            )
            result = self.algorithm_selector.run_algorithm(
                algorithm, message, key, include_special_chars
            )

            # Ensure `result_output` exists
            if self.result_output.winfo_exists():
                self.result_output.delete("1.0", "end")
                self.result_output.insert("1.0", result)

            # Handle generated keys
            if self.algorithms[algorithm].get("generated_key", False):
                generated_key = self.algorithm_selector.get_generated_key(algorithm)
                if generated_key:
                    # Safely reset or recreate `generated_key_output`
                    self.reset_generated_key_output()

                    # Create a new frame inside `generated_key_output` for buttons
                    button_frame = ctk.CTkFrame(self.generated_key_output)
                    button_frame.grid(row=0, column=0, sticky="nsew")

                    # Add buttons for each key inside the new frame
                    for key_name, key_value in generated_key.items():
                        key_button = ctk.CTkButton(
                            button_frame,
                            text=key_name,
                            command=lambda k_name=key_name, k_value=key_value: self.show_key_popup(k_name, k_value)
                        )
                        key_button.grid(pady=5, padx=5, sticky="w")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def show_key_popup(self, title, key_content):
        """ Show a popup window displaying the full content of a key or IV. """
        popup = ctk.CTkToplevel(self)  # Create a new popup window
        popup.title(title)
        popup.geometry("400x300")

        # Add a scrollable text widget to display the key content
        key_display = ctk.CTkTextbox(popup, width=400, height=300)
        key_display.insert("1.0", key_content)  # Insert the key content
        key_display.configure(state="disabled")  # Make it read-only
        key_display.pack(fill="both", expand=True)  # Make the text box fill the window

        # Add the popup to the list of open popups
        self.open_popups.append(popup)

        # Handle popup window closure
        def on_close():
            self.close_popup(popup)

        popup.protocol("WM_DELETE_WINDOW", on_close)  # Ensure manual closure works

    def close_popup(self, popup):
        """Close a specific popup."""
        if popup in self.open_popups:
            if popup.winfo_exists():
                popup.destroy()
            self.open_popups.remove(popup)  # Remove from the list after closing

    def close_all_popups(self):
        """Close all currently open popups."""
        for popup in self.open_popups:
            if popup.winfo_exists():
                popup.destroy()
        self.open_popups.clear()  # Clear the list of popups after closing them

    def reset_generated_key_output(self):
        """
        Safely destroy and recreate the `generated_key_output` widget to avoid invalid references.
        """
        # Destroy the existing widget if it exists
        if hasattr(self, "generated_key_output") and self.generated_key_output.winfo_exists():
            self.generated_key_output.destroy()

        # Recreate the widget
        self.generated_key_output = ctk.CTkTextbox(self, width=400, height=30)
        self.generated_key_output.grid(row=4, column=1, padx=10, pady=10)
        self.generated_key_output.bind("<Key>", lambda e: "break")  # Read-only


if __name__ == "__main__":
    selector = AlgorithmSelector()
    app = AlgorithmApp(selector)
    app.mainloop()