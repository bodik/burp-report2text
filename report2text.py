"""
Burp extension report2text

## References

* https://laconicwolf.com/2019/03/09/burp-extension-python-tutorial-generate-a-forced-browsing-wordlist/
* https://parsiya.net/blog/2019-11-26-swing-in-python-burp-extensions-part-3-tips-and-tricks/#create-a-context-menu
* https://github.com/laconicwolf/burp-extensions
"""

from burp import IBurpExtender, IContextMenuFactory, ITab
from java.awt import BorderLayout, Color
from java.awt.event import ActionListener, FocusListener
from java.util import ArrayList
from javax.swing import JMenuItem, JPanel, JScrollPane, JTextArea


__version__ = '0.0.2'


class ReportToTextMenuListener(ActionListener):
    """ActionListener for the Burp context menu."""

    def __init__(self, extension, invocation):
        self.extension = extension
        self.invocation = invocation

    def actionPerformed(self, event):
        """Invoked when the context menu item is selected."""

        output = []
        for issue in self.invocation.getSelectedIssues():
            output.append('----')
            output.append('## Report %d: %s\n' % (issue.getIssueType(), issue.getIssueName()))
            output.append('url: %s\n' % issue.getUrl())
            output.append('### Background\n\n%s\n' % issue.getIssueBackground())
            output.append('### Detail\n\n%s\n' % issue.getIssueDetail())
            output.append('### Requests\n')
            for idx, request in enumerate(issue.getHttpMessages()):
                output.append('### Request %d\n' % idx)
                output.append('```\n%s\n```\n' % self.extension._helpers.bytesToString(request.getRequest()))
                output.append('```\n%s\n```\n' % self.extension._helpers.bytesToString(request.getResponse()))

        self.extension.setReportText('\n'.join(output))


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, FocusListener):
    """custom reporting extension implementation"""

    def registerExtenderCallbacks(self, callbacks):
        """extension startup"""

        # commons
        self.EXTENSION_NAME = 'Report2text'
        self.COLOR_RED = Color(0xff6633)
        self.COLOR_BLACK = Color(0x0)

        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName(self.EXTENSION_NAME)

        # menu
        self._callbacks.registerContextMenuFactory(self)

        # output tab
        self._mainTextArea = JTextArea('initial text')
        self._mainTextArea.editable = False
        self._mainTextArea.setLineWrap(True)
        self._mainTextArea.setWrapStyleWord(True)
        self._mainTextArea.addFocusListener(self)

        self._tab = JPanel(BorderLayout())
        self._tab.add(JScrollPane(self._mainTextArea))
        self._callbacks.addSuiteTab(self)

        return

    def createMenuItems(self, invocation):
        """iface IContextMenuFactory; context menu handler"""

        menuItems = ArrayList()
        if invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS:
            menuItem = JMenuItem('Report2text')
            menuItem.addActionListener(ReportToTextMenuListener(self, invocation))
            menuItems.add(menuItem)
        return menuItems

    def getTabCaption(self):
        """iface ITab; Return the text to be displayed on the tab"""
        
        return self.EXTENSION_NAME
                                
    def getUiComponent(self):
        """iface ITab; Passes the UI to burp"""

        return self._tab

    def focusGained(self, event):
        """iface FocusListener; reset color on tab focus"""

        self._setTabBackground(self.COLOR_BLACK)

    def setReportText(self, text):
        """set report text"""

        self._setTabBackground(self.COLOR_RED)
        self._mainTextArea.text = text

    def _setTabBackground(self, color):
        """set tab caption background"""

        tabbedPane = self.getUiComponent().getParent()
        for idx in range(tabbedPane.getTabCount()):
            if tabbedPane.getTitleAt(idx) == self.EXTENSION_NAME:
                tabbedPane.setBackgroundAt(idx, color);
