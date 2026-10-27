import os
import unittest
from unittest.mock import patch
import server

class PathTests(unittest.TestCase):
    def test_explicit_paths_win_over_path_discovery(self):
        with patch.dict(os.environ, {"DAFEIYU_DOCKER_EXE": "X:/Custom/docker.exe", "DAFEIYU_DESKTOP_EXE": "X:/Custom/Docker Desktop.exe"}), patch.object(server.shutil, "which", return_value="Y:/docker.exe"):
            self.assertEqual(server.resolve_docker_paths(), ("X:/Custom/docker.exe", "X:/Custom/Docker Desktop.exe"))

    def test_path_installation_does_not_require_original_d_drive(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(server.shutil, "which", return_value="C:/Tools/docker.exe"), patch.object(server.Path, "is_file", return_value=False):
            docker, desktop = server.resolve_docker_paths()
            self.assertEqual(docker, "C:/Tools/docker.exe")
            self.assertIn("Docker Desktop.exe", desktop)

if __name__ == "__main__":
    unittest.main()
