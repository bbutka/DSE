import sys
import os

# Add the parent of dse_tool (HOST26_Code) to sys.path so that
# 'from dse_tool.gui.X import ...' works correctly from main_window.py,
# and the relative imports inside network_editor.py (from ..core ...) also resolve.
_parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _parent_dir not in sys.path:
    sys.path.insert(0, _parent_dir)

from dse_tool.gui.main_window import MainWindow

if __name__ == "__main__":
    app = MainWindow()
    app.mainloop()
