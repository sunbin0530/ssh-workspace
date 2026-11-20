"""Exercise the actual Tk layout at several text scalings, without SSH."""
import tkinter as tk
import unittest

from dialog_layout import review_layout


class DialogLayoutTests(unittest.TestCase):
    def test_actions_stay_visible_with_large_text_and_small_window(self):
        root = tk.Tk()
        root.withdraw()
        try:
            for scale in (1.0, 1.5, 2.0):
                root.tk.call('tk', 'scaling', scale)
                dialog, preview, actions = review_layout(root, 'Layout test', 'Long command review', 'x' * 20000)
                buttons = [tk.Button(actions, text=text) for text in ('取消，不执行', '确认执行（含删除）')]
                for index, button in enumerate(buttons):
                    button.grid(row=0, column=index, sticky='w' if index == 0 else 'e')
                dialog.geometry('640x300')
                dialog.update()
                self.assertTrue(actions.winfo_ismapped())
                self.assertGreater(preview.winfo_height(), 0)
                self.assertLessEqual(actions.winfo_y() + actions.winfo_height(), dialog.winfo_height())
                for button in buttons:
                    self.assertTrue(button.winfo_ismapped())
                    self.assertLessEqual(button.winfo_x() + button.winfo_width(), actions.winfo_width())
                dialog.destroy()
        finally:
            root.destroy()


if __name__ == '__main__':
    unittest.main()
