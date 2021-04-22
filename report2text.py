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

        self.extension.setTabBackground(self.extension.COLOR_RED)
        self.extension.tab_main_text.text = '\n'.join(output)


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, FocusListener):
    """custom reporting extension implementation"""

    def registerExtenderCallbacks(self, callbacks):
        """extension startup"""

        # commons
        self.extension_name = 'Report2text'
        self.COLOR_RED = Color(0xff6633)
        self.COLOR_BLACK = Color(0x0)

        self._callbacks = callbacks
        self._helpers = self._callbacks.getHelpers()
        self._callbacks.setExtensionName(self.extension_name)

        # menu
        self._callbacks.registerContextMenuFactory(self)

        # output tab
        self.tab_main_text = JTextArea('initial text')
        self.tab_main_text.editable = False
        self.tab_main_text.setLineWrap(True)
        self.tab_main_text.setWrapStyleWord(True)
        self.tab_main_text.addFocusListener(self)

        self.tab = JPanel(BorderLayout())
        self.tab.add(JScrollPane(self.tab_main_text))
        self._callbacks.addSuiteTab(self)

        return

    def createMenuItems(self, invocation):
        """IContextMenuFactory; context menu handler"""

        menu = ArrayList()
        if invocation.getInvocationContext() == invocation.CONTEXT_SCANNER_RESULTS:
            report_to_text_menu_item = JMenuItem('Report2text')
            report_to_text_menu_item.addActionListener(ReportToTextMenuListener(self, invocation))
            menu.add(report_to_text_menu_item)

        return menu

    def getTabCaption(self):
        """ITab; Return the text to be displayed on the tab"""
        
        return 'Report2text'
                                
    def getUiComponent(self):
        """ITab; Passes the UI to burp"""

        return self.tab

    def setTabBackground(self, color):
        """set tab caption background"""

        tabbed_pane = self.getUiComponent().getParent()
        for idx in range(tabbed_pane.getTabCount()):
            if tabbed_pane.getTitleAt(idx) == self.extension_name:
                tabbed_pane.setBackgroundAt(idx, color);

    def focusGained(self, event):
        """FocusListener; reset color on tab focus"""

        self.setTabBackground(self.COLOR_BLACK)
