"""
@license:

@author: Peter Kabiri
"""

### IMPORTS
import ConfigParser
import os
import sys
import shutil
import inspect

from ndsatcom.products.skywanng.SkywaniduNg import SkywaniduNg

from ndsatcom.projects.systemtest.skywanng.encryption.GRETunnelEncryption.api.TestCenterProcessor import TestCenterProcessor


### GLOBAL DEFINES

### CLASS
class Environment(object):
    """
    Base class for Environment
    """


    def __init__(self, dictionary):
        """
        Create a new instance of Environment

        @param dictionary: project dictionary
        @type  dictionary: Dictionary
        """


    def get_workspace(self):
        """
        Get the workspace directory

        @return: the workspace directory
        @rtype:  String
        """
        workspace_subfolder = '/tmp/testoutput'
        return workspace_subfolder
        
    def get_project_folder(self):
        """
        Get the project folder -> workspace + project_name

        @return: the project folder
        @rtype:  String
        """
        workspace = self.get_workspace()

        foldername = os.path.split(self.__base_path)[-1]

        return os.path.join(workspace, foldername)



###  Start of __main__ / local testing  ###
if __name__ == "__main__":


    print "Get workspace path:"
    print ENV.get_workspace()

    print "Get project folder:"
    print ENV.get_project_folder()

    print ">>> End of Test <<<"
