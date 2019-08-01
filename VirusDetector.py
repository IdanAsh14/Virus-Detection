from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import os
import requests


class Feedback:
    def __init__(self, master):
        # In the __init__ we initialize the VirusDetector GUI
        # The initialization includes labels, radio buttons, textbox, buttons and progress bar

        self.root = master
        master.title('Virus Scanner')
        master.resizable(False, False)
        # Create the background
        master.configure(background='#e1d8b9')
        self.style = ttk.Style()
        # Creating the configuration of the GUI style
        self.style.configure('TFrame', background='#e1d8b9')
        self.style.configure('TButton', background='#e1d8b9')
        self.style.configure('TRadiobutton', font=('Arial', 10), background='#e1d8b9')
        self.style.configure('TLabel', background='#e1d8b9', font=('Arial', 11))
        self.style.configure('Header.TLabel', font=('Arial', 18, 'bold'))
        # Api key for the virus scanner
        self.api_key = 'ENTER YOU API HERE'
        self.params = {'apikey': self.api_key}
        self.http = 0   # If http is 0 => URL if http is 1 => file from the pc
        self.frame_header = ttk.Frame(master)
        self.frame_header.pack()
        # The logo for the program
        self.logo = PhotoImage(file='data-2548657_640.gif')
        ttk.Label(self.frame_header, image=self.logo).grid(row=0, column=0, rowspan=2)
        ttk.Label(self.frame_header, text='Virus scanner!', style='Header.TLabel').grid(row=0, column=1)
        ttk.Label(self.frame_header, wraplength=280,
                  text=(
                  "I'm glad you chose to use the virus scanner by Idan. Please Choose a file from your"
                  " pc or a url.")).grid(row=1, column=1)

        self.frame_content = ttk.Frame(master)
        self.frame_content.pack()
        # init the radio buttons and the textbox of the GUI.
        self.file_type = StringVar()
        self.file_type.set('file_path')
        ttk.Radiobutton(self.frame_content, text='File Path', variable=self.file_type, value='file_path').grid(row=0,
                                                                                                               column=0,
                                                                                                               padx=5,
                                                                                                               sticky='sw')
        ttk.Radiobutton(self.frame_content, text='URL', variable=self.file_type, value='url').grid(row=0, column=1,
                                                                                                   padx=5, sticky='sw')
        self.results_label = ttk.Label(self.frame_content, text='Results:')
        self.results_label.grid(row=2, column=0, padx=5, sticky='sw')
        self.results_label.grid_remove()

        self.entry_file_name = ttk.Entry(self.frame_content, width=24, font=('Arial', 10))
        self.entry_url = ttk.Entry(self.frame_content, width=24, font=('Arial', 10))
        self.text_results = Text(self.frame_content, width=50, height=10, font=('Arial', 10))

        self.entry_file_name.grid(row=1, column=0, padx=5)
        self.entry_url.grid(row=1, column=1, padx=5)
        self.text_results.grid(row=3, column=0, columnspan=2, padx=5)
        self.scrollbar = ttk.Scrollbar(self.frame_content, orient=VERTICAL, command=self.text_results.yview)
        self.scrollbar.grid(row=3, column=2, sticky='ns')
        self.text_results.config(yscrollcommand=self.scrollbar.set)
        self.text_results.grid_remove()
        self.scrollbar.grid_remove()
        self.progress_bar = ttk.Progressbar(self.frame_content, orient=HORIZONTAL, length=360)

        self.scan_button = ttk.Button(self.frame_content, text='Scan',
                                      command=self.submit)
        self.scan_button.grid(row=4, column=0, padx=5, pady=5, sticky='e')
        self.clear_button = ttk.Button(self.frame_content, text='Clear',
                                       command=self.clear)
        self.clear_button.grid(row=4, column=1, padx=5, pady=5, sticky='w')

    def exit_program(self):
        exit(0)

    def submit(self):
        # The function is activated once we click the Scan button.
        # Check if the file is URL or a file from the PC, and then activating the right function

        self.text_results.grid_remove()
        self.progress_bar.grid_remove()
        self.progress_bar.grid(row=3, column=0, columnspan=2, pady=5, padx=5)
        self.progress_bar.config(mode='indeterminate')
        self.progress_bar.start()
        self.procced = 0

        # Check if it's file from the pc
        if (self.file_type.get() == 'file_path'):
            self.get_file_path()
            self.http = 0
        else:
            # if it's not a file from the pc, it's URL
            self.http = 1
            messagebox.showinfo(title='File submitted',
                                message='Hey, Thank you! Please wait, we are scanning the file!')
            self.scan_url(self.entry_url.get())
            self.procced = 1

        # If the file is valid, start the scanning
        if(self.procced ==1):
            self.scan_viruses()
            self.clear()
            self.show_results()

    def start_prog_bars(self):
        # Initialize the progress bar
        self.scan_button.grid_remove()
        self.clear_button.grid_remove()
        self.progress_bar.grid(row=3, column=0, columnspan=2, pady=5, padx=5)
        self.progress_bar.config(mode='indeterminate')
        self.progress_bar.start()

    def scan_viruses(self):
        # Call the virus scanner function
        self.active_scan()


    def show_results(self):
        # once we have the Results, the function writes the results to the Text box in the GUI
        self.results_label.grid()
        self.scrollbar.grid()
        self.text_results.grid()
        with open("ScanResult.txt", "r") as ins:
            for line in ins:
                self.text_results.insert(END, line)

    def clear(self):
        # Once the user click the clear button , the function clears the text box , the file_path and URL labels and clears and progress bar
        self.entry_file_name.delete(0, 'end')
        self.entry_url.delete(0, 'end')
        self.text_results.delete(1.0, 'end')
        self.results_label.grid_remove()
        self.scrollbar.grid_remove()
        self.text_results.grid_remove()
        self.progress_bar.stop()
        self.progress_bar.grid_remove()
        self.scan_button.grid()
        self.clear_button.grid()

    def get_file_path(self):
        # Check if the file path is valid
        if(os.path.exists(self.entry_file_name.get())): # Check if the file exits in the pc
            self.file_path = self.entry_file_name.get()
            self.procced = 1
            messagebox.showinfo(title='File submitted',
                                message='Hey, Thank you! Please wait, we are scanning the file!')
            self.scan_file(self.file_path)


        else:   # If the file does not exist , open the brower and let the user select again the file
            self.file_path = filedialog.askopenfile()
            if (self.file_path is None):
                self.clear()
            else:
                messagebox.showinfo(title='File submitted', message='Please wait, we are scanning the file!')
                self.scan_file(self.file_path.name)
                self.procced = 1


    def scan_url(self, url):
        # If it's URL , set a request to virus total and state that we are scanning URL
        self.file_path = url
        self.http = 1
        self.params = {'apikey': self.api_key, 'url': url}
        self.response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=self.params)
        self.json_response = self.response.json()
        self.resource_id = url
        self.params = {'apikey': self.api_key, 'resource': self.resource_id}
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        try:
            self.response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                                      params=self.params, headers=self.headers)
        except:
            pass

    def scan_file(self, file_path):
        self.file_path = file_path
        self.files = {'file': (file_path, open(file_path, 'rb'))}
        self.response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=self.files,
                                      params=self.params)
        self.json_response = self.response.json()
        self.resource_id = self.json_response[u'resource']
        self.params = {'apikey': self.api_key, 'resource': self.resource_id}
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  My Python requests library example client or username"
        }
        try:
            self.response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                        params=self.params, headers=self.headers)
        except:
            pass

    def active_scan(self):
        # Activate The scan of the file.
        # While the algorithm scan's the file , we stay in while loop. once the response message is true , we know the scan is finished
        # When the scan is finished , we decode the JSON file and write the results in a pretty manner to txt file
        self.start_prog_bars()
        self.json_response = self.response.json()
        self.progress_bar['value'] = 20
        self.root.update_idletasks()

        # While false , the file is hasn't fully scanned yet.

        while (('Scan finished' in self.json_response[u'verbose_msg']) == False):
            print("Scanning ,Please wait...")
            # Every iteration we update the progress bsr
            self.progress_bar['value'] = self.progress_bar['value'] + 10
            self.root.update_idletasks()
            # If it's url post a URL request
            if self.http == 1:
                self.response = requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                                              params=self.params, headers=self.headers)
            else:
                # Else post a regular request
                self.response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
                                             params=self.params, headers=self.headers)
            try:
                self.json_response = self.response.json()
            except:
                pass
        # We get here once the scan is finished.
        # Write to txt the results from the JSON file
        f = open('ScanResult.txt', 'w')
        f.write("Scanned:", )
        f.write(self.file_path)
        f.write("\n")
        for key, value in (self.json_response[u'scans']).items():
            f.write(key, )
            f.write(": ", )
            # If there is no virus we write it
            if (value[u'detected'] == False):
                f.write("No virus found\n")
            else:
                # If we found virus , we write the virus details and the virus name
                f.write("Found virus: ", )
                f.write(value[u'result'])
                f.write("\n")
        messagebox.showinfo(title='Scan finished', message='Scan finished, check ScanResult.txt for the results!!')


def main():
    # Initialize the GUI and the VirusDetector
    root = Tk()
    feedback = Feedback(root)
    root.mainloop()


if __name__ == "__main__": main()
