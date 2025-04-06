from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Configure OpenTelemetry
trace.set_tracer_provider(TracerProvider())
exporter = OTLPSpanExporter(
    endpoint="https://ingest.in.signoz.cloud:443",
    headers={"signoz-ingestion-key": "2c0b2eac-9c16-41c3-9a91-8b4050dc3065y"},
)
span_processor = BatchSpanProcessor(exporter)
trace.get_tracer_provider().add_span_processor(span_processor)

# Your existing ransomware detection logic starts here

import tkinter as tk 
from tkinter import filedialog, messagebox, Text 
from tkinter import ttk 
from tkinter import PhotoImage 
import pefile 
import pandas as pd 
import joblib  # For loading the saved model and scaler 
import os 
 
class RansomwareDetectorApp: 
    def __init__(self, root): 
        self.root = root 
        self.root.title("Ransomware Detector") 
        self.root.geometry("1300x800") 
        self.root.configure(bg="#D0DEF2") 
        icon = PhotoImage(file="ransomware.png") 

        self.root.iconphoto(True, icon) 
         
        # Center window on the screen 
        screen_width = root.winfo_screenwidth() 
        screen_height = root.winfo_screenheight() 
        x_position = (screen_width - 1300) // 2 
        y_position = (screen_height - 850) // 2 
        root.geometry(f"1300x800+{x_position}+{y_position}") 
 
        # Title 
        title = tk.Label(root, text="RANSOMWARE DETECTOR", font=("Segoe UI Black", 50), fg="#21569B", bg="#D0DEF2") 
        title.place(x=210, y=20) 
 
        # Display for file properties 
        self.display = tk.Text(root, font=("Candara", 25), fg="#004093", bg="white", wrap="word", width=35, height=15.47) 
        self.display.insert("1.0", "*********** FILE PROPERTIES ***********\n") 
        self.display.configure(state="disabled") 
        self.display.place(x=625, y=150) 
        self.display.config( bd=0, relief="solid",highlightthickness=4, highlightbackground="#01367C", highlightcolor="#01367C") 
 
        # File selection label and button 
        tk.Label(root, text="Select the file:", font=("Arial", 20, "bold"), fg="#07397A", bg="#D0DEF2").place(x=100, y=210) 
        browse_button = tk.Button(root, text="BROWSE", command=self.select_file, font=("Arial", 18,"bold"), bg="#A1C9FC", fg="#063675",width=15,height=2) 
        browse_button.place(x=310, y=193) 
 
        # Selected file label and display 
        tk.Label(root, text="File Selected:", font=("Arial", 20, "bold"), fg="#07397A", bg="#D0DEF2").place(x=40, y=330) 
        self.file_display = tk.Text(root, font=("Arial", 18), width=43,height=4,background="#D0DEF2",fg="#07397A",wrap="word") 
        self.file_display.place(x=40, y=375) 
         
        # Result output label 
        tk.Label(root, text="RESULT:", font=("Arial", 20, "bold"), fg="#07397A", bg="#D0DEF2").place(x=103, y=561) 
        self.output = tk.StringVar() 
        self.output_display = tk.Label(root, textvariable=self.output, font=("Arial", 25, "bold"), fg="white", bg="#D0DEF2", width=13, justify="center",bd=2,relief="solid") 
        self.output_display.place(x=255, y=557) 
 
        # Scan button 
        scan_button = tk.Button(root, text="SCAN", command=self.scan_file, font=("Arial", 20, "bold"), bg="#A1C9FC", fg="#063675", width=10) 
        scan_button.place(x=230, y=670) 
 
        # Load pre-trained model, scaler, and feature column names 
        self.model = joblib.load('ransomware_model.pkl') 
        self.scaler = joblib.load('scaler.pkl') 
 
        # Load the column names from the training data (X columns) 
        self.columns = pd.read_csv(r"ransomware_dataset.csv").drop(columns=['FileName', 'md5Hash']).drop(columns=['Benign']).columns 
 
    def select_file(self): 
        self.path = filedialog.askopenfilename(filetypes=[("Executable Files", "*.exe"), ("DLL Files", "*.dll"), ("Binary Files", "*.bin")]) 
        if self.path: 
            self.file_display.configure(state="normal")  # Enable the Text widget 
            self.file_display.delete("1.0", tk.END)  # Correctly delete all content 
            self.file_display.insert("1.0", self.path)  # Insert the new file path 
            self.file_display.configure(state="disabled")  # Disable it again 
 
    def scan_file(self): 
        if not hasattr(self, 'path') or not self.path: 
            messagebox.showerror("Error", "Please select a file to scan.") 
            return 
        features, extracted_features = self.extract_features(self.path)  # Get both DataFrame and extracted features 
        if features is not None and not features.empty: 
            features_scaled = self.scaler.transform(features) 
            prediction = self.model.predict(features_scaled) 
            self.display_result(prediction, extracted_features)  # Pass extracted features here 
        else: 
            messagebox.showerror("Error", "Failed to extract features from the file.") 
 
    def display_result(self, prediction, extracted_features): 
        self.display.configure(state="normal") 
        self.display.delete("1.0", tk.END) 
        self.display.insert("1.0", "*********** FILE PROPERTIES ***********\n") 
     
        file_name = os.path.basename(self.path) 
        self.display.insert("2.0", "\n") 
        self.display.insert("3.0", f"File: {file_name}\n") 
        self.display.insert("4.0", f"Machine: {extracted_features['Machine']}\n") 
        self.display.insert("6.0", f"Debug Size: {extracted_features['DebugSize']}\n") 
        self.display.insert("7.0", f"Major OS Version: {extracted_features['MajorOSVersion']}\n") 
        self.display.insert("8.0", f"Export Size: {extracted_features['ExportSize']}\n") 
        self.display.insert("9.0", f"Number of Sections: {extracted_features['NumberOfSections']}\n") 
        self.display.insert("10.0", f"Resource Size: {extracted_features['ResourceSize']}\n") 
        self.display.configure(state="disabled") 
 
        # Determine prediction and change output display 
        if prediction[0] == 1:  # SAFE 
            self.output.set("SAFE") 
            self.output_display.configure(bg="green")  # Set background color to green 
        else:  # RANSOMWARE 
            self.output.set("RANSOMWARE") 
            self.output_display.configure(bg="red")  # Set background color to red 
 
            # Prompt to delete the file if ransomware detected 
            self.ask_to_delete_file() 
 
        self.output_display.configure() 
 
    def ask_to_delete_file(self): 
        response = messagebox.askyesno("Ransomware Detected", "This file is detected as ransomware. Do you want to delete it?") 
        if response: 
            try: 
                # Ensure the PE file is closed before deleting 
                if hasattr(self, 'pe_file') and self.pe_file is not None: 
                    self.pe_file.close() 
                os.remove(self.path)  # Delete the file 
                messagebox.showinfo("File Deleted", f"The file {os.path.basename(self.path)} has been deleted.") 
            except Exception as e: 
                messagebox.showerror("Error", f"Failed to delete the file: {str(e)}") 
 
    def extract_features(self, file_path): 
        try: 
            # Open the PE file 
            self.pe_file = pefile.PE(file_path) 
            features = { 
                'Machine': self.pe_file.FILE_HEADER.Machine, 
                'DebugSize': getattr(self.pe_file.OPTIONAL_HEADER, 'SizeOfHeaders', 0), 
                'DebugRVA': getattr(self.pe_file.OPTIONAL_HEADER, 'BaseOfCode', 0), 
                'MajorImageVersion': getattr(self.pe_file.OPTIONAL_HEADER, 'MajorImageVersion', 0), 
                'MajorOSVersion': getattr(self.pe_file.OPTIONAL_HEADER, 'MajorOperatingSystemVersion', 0), 
                'ExportRVA': getattr(self.pe_file.OPTIONAL_HEADER, 'AddressOfEntryPoint', 0), 
                'ExportSize': getattr(self.pe_file.OPTIONAL_HEADER, 'SizeOfImage', 0), 
                'IatVRA': getattr(self.pe_file.OPTIONAL_HEADER, 'ImageBase', 0), 
                'MajorLinkerVersion': getattr(self.pe_file.OPTIONAL_HEADER, 'MajorLinkerVersion', 0), 
                'MinorLinkerVersion': getattr(self.pe_file.OPTIONAL_HEADER, 'MinorLinkerVersion', 0), 
                'NumberOfSections': getattr(self.pe_file.FILE_HEADER, 'NumberOfSections', 0), 
                'SizeOfStackReserve': getattr(self.pe_file.OPTIONAL_HEADER, 'SizeOfStackReserve', 0), 
                'DllCharacteristics': getattr(self.pe_file.OPTIONAL_HEADER, 'DllCharacteristics', 0), 
                'ResourceSize': sum(entry.directory.entries[0].data.struct.Size for entry in self.pe_file.DIRECTORY_ENTRY_RESOURCE.entries if hasattr(entry, 'data') and hasattr(entry.data, 'struct') and hasattr(entry.data.struct, 'Size')) if hasattr(self.pe_file, 'DIRECTORY_ENTRY_RESOURCE') else 0, 
                'BitcoinAddresses': 0 
            } 
            features_df = pd.DataFrame([features], columns=self.columns).fillna(0) 
            return features_df, features  # Return both DataFrame and the features dictionary 
        except Exception as e: 
            print(f"Error processing file {file_path}: {str(e)}") 
            return None, {}  # Return an empty DataFrame and dictionary in case of an error 
 
# Start the application 
root = tk.Tk() 
app = RansomwareDetectorApp(root) 
root.mainloop()  