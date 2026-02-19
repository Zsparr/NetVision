import os
import customtkinter as ctk
from ui import NetworkScannerApp


SPLASH_DURATION_MS = 15_000


class StartupSplash(ctk.CTkToplevel):
    def __init__(self, master, duration_ms=SPLASH_DURATION_MS):
        super().__init__(master)
        self.master = master
        self.duration_ms = max(0, int(duration_ms))
        self._spinner_frames = ["|", "/", "-", "\\"]
        self._spinner_index = 0
        self._finished = False
        self._elapsed_ms = 0

        self.title("Starting NetVision")
        self.geometry("420x220")
        self.resizable(False, False)
        self.configure(fg_color="#121826")
        self.protocol("WM_DELETE_WINDOW", self._cancel_startup)

        container = ctk.CTkFrame(self, fg_color="transparent")
        container.pack(expand=True, fill="both", padx=20, pady=20)

        ctk.CTkLabel(
            container,
            text="NetVision",
            font=("Segoe UI", 28, "bold"),
            text_color="#4fc3f7",
        ).pack(pady=(6, 8))

        ctk.CTkLabel(
            container,
            text="Loading network modules...",
            font=("Segoe UI", 14),
            text_color="#bdbdbd",
        ).pack(pady=(0, 10))

        self.spinner_label = ctk.CTkLabel(
            container,
            text="|",
            font=("Consolas", 40, "bold"),
            text_color="#66bb6a",
        )
        self.spinner_label.pack(pady=(0, 8))

        self.timer_label = ctk.CTkLabel(
            container,
            text=f"{self.duration_ms // 1000}s",
            font=("Segoe UI", 13),
            text_color="#9e9e9e",
        )
        self.timer_label.pack()

        self.after(10, self._center_on_screen)
        self._animate_spinner()
        self._start_countdown()
        self.after(self.duration_ms, self._finish_startup)

    def _center_on_screen(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() - width) // 2
        y = (self.winfo_screenheight() - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        self.lift()
        self.attributes("-topmost", True)
        self.after(100, lambda: self.attributes("-topmost", False))

    def _animate_spinner(self):
        if self._finished or not self.winfo_exists():
            return
        self.spinner_label.configure(text=self._spinner_frames[self._spinner_index])
        self._spinner_index = (self._spinner_index + 1) % len(self._spinner_frames)
        self.after(120, self._animate_spinner)

    def _start_countdown(self):
        if self._finished or not self.winfo_exists():
            return
        remaining = max(0, self.duration_ms - self._elapsed_ms)
        self.timer_label.configure(text=f"{(remaining + 999) // 1000}s")
        self._elapsed_ms += 250
        if remaining > 0:
            self.after(250, self._start_countdown)

    def _finish_startup(self):
        if self._finished:
            return
        self._finished = True
        if self.winfo_exists():
            self.destroy()
        self.master.deiconify()
        self.master.lift()
        self.master.focus_force()

    def _cancel_startup(self):
        self._finished = True
        self.master.destroy()


if __name__ == "__main__":
    app = NetworkScannerApp()
    app.withdraw()
    splash_ms = int(os.environ.get("NETVISION_SPLASH_MS", str(SPLASH_DURATION_MS)))
    StartupSplash(app, duration_ms=splash_ms)
    app.mainloop()
