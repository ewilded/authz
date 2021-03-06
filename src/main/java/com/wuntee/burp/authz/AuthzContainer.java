package com.wuntee.burp.authz;

import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableCellRenderer;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpRequestResponsePersisted;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import javax.swing.JCheckBox;



public class AuthzContainer extends Container {
	private static final long serialVersionUID = 31337L;        
	private JTable requestTable;
	private JTable responseTable;

        private String[] headersToReplace;
        private String[] namesOfHeadersToReplace;
        
	private TabbedHttpEditor originalRequest;
	private TabbedHttpEditor originalResponse;
	private TabbedHttpEditor modifiedRequest;
	private TabbedHttpEditor responseEditor;
	private BurpTextEditorWithData cookieEditor;
        private JCheckBox chkbxExtendedChecks;

	private DefaultTableModel requestTableModel;
	private DefaultTableModel responseTableModel;

	private IBurpExtenderCallbacks burpCallback;

	public static String REQUEST_OBJECT_KEY = "req_obj_key";
	public static String RESPONSE_OBJECT_KEY = "resp_obj_key";
	private static Object[] REQUEST_HEADERS = new Object[]{"#", "Method", "URL", "Parms", "Response Code", REQUEST_OBJECT_KEY};
	private static Object[] RESPONSE_HEADERS = new Object[]{"#", "Method", "URL", "Bypass method","Orig Response Size", "Response Size", "Orig Return Code", "Return Code", "Diff Bytes", "Similarity", REQUEST_OBJECT_KEY, RESPONSE_OBJECT_KEY};
	public static String TEXTEDITOR_REQUET_KEY = IHttpRequestResponse.class.toString();

        private PrintWriter output;
        
	public AuthzContainer(final IBurpExtenderCallbacks burpCallback) {

		this.burpCallback = burpCallback;
                this.output =  new PrintWriter(burpCallback.getStdout(),true);            			
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWeights = new double[]{1.0};
		gridBagLayout.rowWeights = new double[]{0, 1.0, 0};
                
		setLayout(gridBagLayout);

		// Create a model that has the Object reference, but do not show the object reference in the GUI
		requestTableModel = new DefaultTableModel(null, REQUEST_HEADERS){
				public boolean isCellEditable(int row, int column) {
						return false;
				}
				public Class<?> getColumnClass(int columnIndex) {
				  return columnIndex == 0 ? Integer.class : Object.class;
				}

		};
		responseTableModel = new DefaultTableModel(null, RESPONSE_HEADERS){
				public boolean isCellEditable(int row, int column) {
						return false;
				}
				public Class<?> getColumnClass(int columnIndex) {
				  return columnIndex == 0 ? Integer.class : Object.class;
				}
		};

		// TABBED PANNEL
		originalRequest = new TabbedHttpEditor(burpCallback);
		originalResponse = new TabbedHttpEditor(burpCallback);
		modifiedRequest = new TabbedHttpEditor(burpCallback);
		responseEditor = new TabbedHttpEditor(burpCallback);


		// COOKIE EDITOR
		JPanel panel_3 = new JPanel();
		GridBagConstraints gbc_panel_3 = new GridBagConstraints();
		gbc_panel_3.fill = GridBagConstraints.BOTH;
		gbc_panel_3.gridx = 0;
		gbc_panel_3.gridy = 0;
		add(panel_3, gbc_panel_3);
		GridBagLayout gbl_panel_3 = new GridBagLayout();
		gbl_panel_3.columnWidths = new int[]{0};
		gbl_panel_3.rowHeights = new int[]{0, 100};
		gbl_panel_3.columnWeights = new double[]{Double.MIN_VALUE};
		gbl_panel_3.rowWeights = new double[]{0, 1};
		panel_3.setLayout(gbl_panel_3);

		JLabel lblNewHeader = new JLabel("New Headers (separate with newline to have multiple headers replaced)", SwingConstants.LEFT);
		GridBagConstraints gbc_lblNewHeader = new GridBagConstraints();
		gbc_lblNewHeader.anchor = GridBagConstraints.WEST;
		gbc_lblNewHeader.insets = new Insets(0, 0, 5, 0);
		gbc_lblNewHeader.gridx = 0;
		gbc_lblNewHeader.gridy = 0;
		panel_3.add(lblNewHeader, gbc_lblNewHeader);

		cookieEditor = new BurpTextEditorWithData(burpCallback);
		cookieEditor.setText("Cookie:".getBytes());
		JScrollPane scrollPane = new JScrollPane(cookieEditor.getComponent());
		GridBagConstraints gbc_scrollPane = new GridBagConstraints();
		gbc_scrollPane.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane.fill = GridBagConstraints.BOTH;
		gbc_scrollPane.gridx = 0;
		gbc_scrollPane.gridy = 1;
		panel_3.add(scrollPane, gbc_scrollPane);


		JSplitPane splitPane = new JSplitPane();
		splitPane.setResizeWeight(0.75);
		splitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
		GridBagConstraints gbc_splitPane = new GridBagConstraints();
		gbc_splitPane.insets = new Insets(0, 0, 5, 0);
		gbc_splitPane.fill = GridBagConstraints.BOTH;
		gbc_splitPane.gridx = 0;
		gbc_splitPane.gridy = 1;
		add(splitPane, gbc_splitPane);

		JPanel panel = new JPanel();
		splitPane.setLeftComponent(panel);

		GridBagLayout gbl_panel = new GridBagLayout();
		gbl_panel.columnWidths = new int[]{0, 0};
		gbl_panel.rowHeights = new int[]{0};
		gbl_panel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel.rowWeights = new double[]{0.0, 1.0, 0.0, 1.0};
		panel.setLayout(gbl_panel);



		// REQUEST PANNEL
		JLabel label_1 = new JLabel("Requests");
		GridBagConstraints gbc_label_1 = new GridBagConstraints();
		gbc_label_1.anchor = GridBagConstraints.WEST;
		gbc_label_1.insets = new Insets(0, 0, 5, 0);
		gbc_label_1.gridx = 0;
		gbc_label_1.gridy = 0;
		panel.add(label_1, gbc_label_1);
		requestTable = new JTable(requestTableModel);

		JPopupMenu popupMenu = new JPopupMenu();
		addPopup(requestTable, popupMenu);
		JMenuItem mntmRemove = new JMenuItem("Remove");
		mntmRemove.addActionListener(new ActionListener(){
			public void actionPerformed(ActionEvent e) {
				int[] selectedRows = requestTable.getSelectedRows();
						if (selectedRows.length > 0) {
								for (int i = selectedRows.length - 1; i >= 0; i--) {
										requestTableModel.removeRow(selectedRows[i]);
								}
						}
			}
		});
		popupMenu.add(mntmRemove);

		JMenuItem mntmRunSelected = new JMenuItem("Run Selected Request(s)");
		mntmRunSelected.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				new Thread(new Runnable(){
					public void run() {
						prepareHeaders();
						for (int rowNum: requestTable.getSelectedRows()) {
							runRequests(getRequestObjectByRow(requestTable, rowNum));                                                        
						}
					}
				}).start();
			}
		});
		popupMenu.add(mntmRunSelected);

		requestTable.setAutoCreateRowSorter(true);
		requestTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		//"Method", "URL", "Parms", "Response Code", REQUEST_OBJECT_KEY
		requestTable.getColumnModel().getColumn(0).setPreferredWidth(30);
		requestTable.getColumnModel().getColumn(1).setPreferredWidth(50);
		requestTable.getColumnModel().getColumn(2).setPreferredWidth(600);
		requestTable.getColumnModel().getColumn(3).setPreferredWidth(50);
		requestTable.getColumnModel().getColumn(4).setPreferredWidth(50);
		requestTable.addMouseListener(new MouseAdapter(){
					 public void mouseClicked(MouseEvent e) {
						 responseTable.clearSelection();
						 setData(getRequestObjectByRow(requestTable, requestTable.getSelectedRow()), null);
					 }
		});
		requestTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent arg0) {
					 responseTable.clearSelection();
					 setData(getRequestObjectByRow(requestTable, requestTable.getSelectedRow()), null);
			}
		});
		requestTable.removeColumn(requestTable.getColumn(REQUEST_OBJECT_KEY));
		JScrollPane scrollPane_1 = new JScrollPane(requestTable);
		GridBagConstraints gbc_scrollPane_1 = new GridBagConstraints();
		gbc_scrollPane_1.insets = new Insets(0, 0, 5, 0);
		gbc_scrollPane_1.fill = GridBagConstraints.BOTH;
		gbc_scrollPane_1.gridx = 0;
		gbc_scrollPane_1.gridy = 1;
		panel.add(scrollPane_1, gbc_scrollPane_1);


		// RESPONSE PANNEL
		JLabel label_2 = new JLabel("Responses");
		GridBagConstraints gbc_label_2 = new GridBagConstraints();
		gbc_label_2.anchor = GridBagConstraints.WEST;
		gbc_label_2.insets = new Insets(0, 0, 5, 0);
		gbc_label_2.gridx = 0;
		gbc_label_2.gridy = 2;
		panel.add(label_2, gbc_label_2);
		responseTable = new JTable(responseTableModel){
			public Component prepareRenderer(TableCellRenderer renderer, int row, int column){
				Component c = super.prepareRenderer(renderer, row, column);

				if (!isRowSelected(row)){
					c.setBackground(getBackground());
					int modelRow = convertRowIndexToModel(row);
					Short returnCode = (Short)getModel().getValueAt(modelRow, ((DefaultTableModel)getModel()).findColumn("Return Code"));
					if(returnCode == 200){
						c.setBackground(Color.GREEN);
					}
				}

				return c;
			}
		};
		responseTable.setAutoCreateRowSorter(true);
		responseTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		//"Method", "URL", "Bypass method","Orig Response Size", "Response Size", "Orig Return Code", "Return Code", "Diff Bytes", REQUEST_OBJECT_KEY, RESPONSE_OBJECT_KEY
		responseTable.getColumnModel().getColumn(0).setPreferredWidth(30);
		responseTable.getColumnModel().getColumn(1).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(2).setPreferredWidth(600);
		responseTable.getColumnModel().getColumn(3).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(4).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(5).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(6).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(7).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(8).setPreferredWidth(50);
		responseTable.getColumnModel().getColumn(9).setPreferredWidth(50);
		responseTable.addMouseListener(new MouseAdapter(){
					 public void mouseClicked(MouseEvent e) {
						 requestTable.clearSelection();
						 setData(getRequestObjectByRow(responseTable, responseTable.getSelectedRow()), 
								 getResponseObjectByRow(responseTable, responseTable.getSelectedRow()));
					 }
		});
		responseTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyReleased(KeyEvent e) {
						 requestTable.clearSelection();
						 setData(getRequestObjectByRow(responseTable, responseTable.getSelectedRow()), 
								 getResponseObjectByRow(responseTable, responseTable.getSelectedRow()));
			}
		});

		new JPopupMenu() {{
			addPopup(responseTable, this);
			add(new JMenuItem("Send to Comparer") {{
				addActionListener(new ActionListener(){
					public void actionPerformed(ActionEvent e) {
						for (int i: responseTable.getSelectedRows()) {
							burpCallback.sendToComparer( getRequestObjectByRow(responseTable, i).getResponse()   );
							burpCallback.sendToComparer( getResponseObjectByRow(responseTable, i).getResponse() );
						}
					}
				});
			}});
		}};

		responseTable.removeColumn(responseTable.getColumn(REQUEST_OBJECT_KEY));
		responseTable.removeColumn(responseTable.getColumn(RESPONSE_OBJECT_KEY));
		JScrollPane scrollPane_2 = new JScrollPane(responseTable);
		GridBagConstraints gbc_scrollPane_2 = new GridBagConstraints();
		gbc_scrollPane_2.fill = GridBagConstraints.BOTH;
		gbc_scrollPane_2.gridx = 0;
		gbc_scrollPane_2.gridy = 3;
		panel.add(scrollPane_2, gbc_scrollPane_2);

		JPanel panel_1 = new JPanel();
		splitPane.setRightComponent(panel_1);
		GridBagLayout gbl_panel_1 = new GridBagLayout();
		gbl_panel_1.columnWidths = new int[]{0, 0};
		gbl_panel_1.rowHeights = new int[]{0, 0};
		gbl_panel_1.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_panel_1.rowWeights = new double[]{1.0, Double.MIN_VALUE};
		panel_1.setLayout(gbl_panel_1);

		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		JScrollPane scrollPane_3 = new JScrollPane(originalRequest);
		tabbedPane.addTab("Original Request", scrollPane_3);		

		tabbedPane.addTab("Original Response", new JScrollPane(originalResponse));
		tabbedPane.addTab("Modified Request", new JScrollPane(modifiedRequest));
		tabbedPane.addTab("Response", new JScrollPane(responseEditor));
		GridBagConstraints gbc_tabbedPane = new GridBagConstraints();
		gbc_tabbedPane.insets = new Insets(0, 0, 5, 0);
		gbc_tabbedPane.fill = GridBagConstraints.BOTH;
		gbc_tabbedPane.gridx = 0;
		gbc_tabbedPane.gridy = 0;
		panel_1.add(tabbedPane, gbc_tabbedPane);

		JPanel panel_2 = new JPanel();
		GridBagConstraints gbc_panel_2 = new GridBagConstraints();
		gbc_panel_2.insets = new Insets(0, 0, 5, 0);
		gbc_panel_2.anchor = GridBagConstraints.SOUTH;
		gbc_panel_2.fill = GridBagConstraints.HORIZONTAL;
		gbc_panel_2.gridx = 0;
		gbc_panel_2.gridy = 2;
		add(panel_2, gbc_panel_2);

		final JButton btnRun = new JButton("Run");
		btnRun.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				new Thread(new Runnable(){
					public void run() {
						btnRun.setEnabled(false);
						runAllRequests();
						btnRun.setEnabled(true);
					}
				}).start();
			}
		});
		GridBagConstraints gbc_btnRun = new GridBagConstraints();
		gbc_btnRun.insets = new Insets(0, 0, 5, 0);
		gbc_btnRun.gridx = 0;
		gbc_btnRun.gridy = 0;
		panel_2.add(btnRun, gbc_btnRun);

		JButton btnClearRequests = new JButton("Clear Requests");
		btnClearRequests.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				clearTable(requestTableModel);
			}
		});
		GridBagConstraints gbc_btnClearRequests = new GridBagConstraints();
		gbc_btnClearRequests.insets = new Insets(0, 0, 5, 0);
		gbc_btnClearRequests.gridx = 1;
		gbc_btnClearRequests.gridy = 0;
		panel_2.add(btnClearRequests, gbc_btnClearRequests);

		JButton btnClearResponses = new JButton("Clear Responses");
		btnClearResponses.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent arg0) {
				clearTable(responseTableModel);
			}
		});
		GridBagConstraints gbc_btnClearResponses = new GridBagConstraints();
		gbc_btnClearResponses.gridx = 2;
		gbc_btnClearResponses.gridy = 0;
                               
                // Extended checks to implement:
                // 1. Null session (no cookies)
                // 2. Path mangling (e.g. adding slashes, dots, mixing cases)
                // 4. Path info mangling
                // 3. Query string mangling (anything more than magic params? - maybe the hash sign (that should never be sent to servers?)               
                // 4. Magic params (Cookies, QUERY_STRING)
                // 5. Magic headers (user agent, X-Forwarded-For, Host??)
                // 6. HTTP methods (e.g. options instead of GET, PUT instead of POST)
                // anything else? different representations of values maybe? encodings, notations???
                
                
                // What is nice about this plugin is that these issues - if present - are in most cases going ot be global for the entire app
                // which means we really need just one round of extended checks.
                
                // Algorithm:
                // 1. Check under legitimate privileges [ STANDARD ]
                // 2. Check under low user privileges   [ STANDARD ]
                // 3. Check under low user privileges with extended checks      [ MY IMPROVEMENT ]
                // 4. If successful, we manually check with null session
                // 5. We can, however, check with null session anyway if we want real thoroughness
                
                chkbxExtendedChecks = new JCheckBox();
                chkbxExtendedChecks.setText("Extended checks");
                chkbxExtendedChecks.setSelected(true);
                GridBagConstraints gbc_chkbxExtendedChecks = new GridBagConstraints();
		gbc_btnClearRequests.insets = new Insets(0, 0, 5, 0);
		gbc_btnClearRequests.gridx = 3;
		gbc_btnClearRequests.gridy = 0;
                
                
		panel_2.add(btnClearResponses, gbc_btnClearResponses);
                panel_2.add(chkbxExtendedChecks, gbc_chkbxExtendedChecks);                
	}

	private void setData(IHttpRequestResponse request, IHttpRequestResponse response){
		originalRequest.clearData();
		originalResponse.clearData();
		modifiedRequest.clearData();
		responseEditor.clearData();

		if(request != null){
			if(request.getRequest() != null){
				originalRequest.loadRequest(request);
			}
			if(request.getResponse() != null){
				originalResponse.loadResponse(request);			
			}
		}
		if(response != null){
			if(response.getRequest() != null){
				modifiedRequest.loadRequest(response);			
			}
			if(response.getResponse() != null){			
				responseEditor.loadResponse(response);
			}
		}

	}

	// For a given request:
        // 1. grab request object
        // 2. do relevant modifications (e.g. replace the cookie)
        // 3. send request
        // 4. add response to response table
	private void runRequests(IHttpRequestResponse req) 
        {
                // From here, we are simply calling the runTransformations() method multiple times (one time per each transformation name).               
                // We are passing the transformation name and the original requestResponse object.
                // This object will be used in two ways:
                // - its request element will be used as a template to forge the attack request
                // - its response element will be used as a pattern to compare the new response with, so we can decide on how to colorize the new request/response to indicate whether there seems to be a vulnerability or not.            
		try 
                {
                        // By now, "headers" is the default transformation.
                        // Also, it occurs for all other transformations too (except for the null session, which overrides the cookies)                        
			runTransformations("headers",req); 
			
                        // Now, the extended checks
                        
                        if(chkbxExtendedChecks.isSelected()==true)
                        {
                            // Will GUI these up once they're working
                            String[] transformations = {"null_session","path","path_info","query_string","magic_params","http_verbs","magic_headers"};
                            for (String transformation: transformations)
                            { 
                                runTransformations(transformation, req); 
                            }
                        }
                        
		} 
                catch (Throwable e) 
                {
			PrintWriter writer = new PrintWriter(burpCallback.getStderr());
			writer.write(e.getMessage());
			writer.write("\n");
			e.printStackTrace(writer);
		}
	}

        private void runTransformations(String transformation, IHttpRequestResponse originalReqResp)
        {
            
            byte[] originalRawRequest = originalReqResp.getRequest(); 
                        
            byte[] maliciousRequest;     // 
            byte[] maliciousRequestBody; // Arrays.copyOfRange(maliciousRawRequest, reqInfo.getBodyOffset(), maliciousRawRequest.length);
            
            IRequestInfo originalReqInfo = burpCallback.getHelpers().analyzeRequest(originalReqResp);
            // header of request should be a string
            List<String> headers = originalReqInfo.getHeaders();
            int indexOfTheCookieHeader=0;
            // iterate over all headers
            
            for(int h=0; h<headers.size(); h++)
            {
                
                // the "headers" transformation is the original mode of operation by this plugin                
                // we have turned it into any header replacement mode
                // then extended it with other modes of potential authorization bypass.
                
                // The algorithm below:
                // 1) iterate over all new headers
                // 2) take notice of the index of the cookie header if present
                // 3) on match, replace the header - whatever its name is
                for(int i=0;i<headersToReplace.length;i++)
                {
                    if(headers.get(h).toLowerCase().startsWith(namesOfHeadersToReplace[i].toLowerCase()))
                    {
                        if(namesOfHeadersToReplace[i].startsWith("Cookie"))
                        {
                            indexOfTheCookieHeader=h;    
                        }
                        // except for "null_session" and the default original cookie replacement mode, ALL other modes should use the original cookie header
                        if(transformation=="headers")
                        {
                            headers.set(h, namesOfHeadersToReplace[i].replace("\n","").replace("\r","") + headersToReplace[i]);                                                          
                        }
                    }
                }
            }
            
            logOutput("[DEBUG] Running '"+transformation+"' transform.");
            
            // We will want to have more requests for some transformations (like path, where there can be different variants)
            // while only having one for others (e.g. null_session)
            // thus all runRequest() calls will be performed individually in each transformation-specific conditional block
                      
            // 1. headers ###############
            if(transformation=="headers")
            {
                // In this case (the basic, original tampering - we only replace the user-defined header list - Cookie by default)
                // So, the request method, URL and body are unchanged.
                maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
                maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
                runRequest(maliciousRequest, originalReqResp, "User-defined header replacement");
                
                return;
            }
            
            // 2. null_session ###############
            if(transformation=="null_session")
            {
                // two variants here:
                // 1. A cookie header without of the original cookies defined
                // 2. No cookie header at all
                
                boolean skipNoCookie=false;
                if(indexOfTheCookieHeader==0) // no cookie header was present in the original request
                {
                    // in this case we need to add it
                    // also, in this case we skip the 2. variant as the original request fullfills it
                    headers.add("Cookie: noneof=theexpected");
                    indexOfTheCookieHeader=headers.size()-1;
                    skipNoCookie=true;
                }
                
                // variant 1.
                headers.set(indexOfTheCookieHeader, "Cookie: noneof=theexpected"); // replace the header with one that does not contain any of the expected values
                maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
                maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
                runRequest(maliciousRequest, originalReqResp, "An empty cookie header");
                
                // variant 2.
                if(skipNoCookie==false)
                {
                    headers.remove(indexOfTheCookieHeader); // remove the header completely
                    maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
                    maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
                    runRequest(maliciousRequest, originalReqResp, "No cookie header at all");                    
                }                                
                // we're done for "null_session"
                return;
            }            
            
            // 3. magic_params ###############
            // "magic_params" is similar, however does not end with cookies,
            // as it as well supports query string parameters.            
            // I guess we'll add them with the "addParameter" API call?
            // appears comfy to code, but won't be good for performance. 
            // On the other hand, there's not so many params to add this way.
            if(transformation=="magic_params")
            {
               // two variants:
               // 1. cookies 
               // whereas we append the cookie header and send it out just like above               
               // 2. query string - whereas we add parameters to the request
               String originalCookieHeader = "";
               if(indexOfTheCookieHeader==0)
               {
                    originalCookieHeader="Cookie: noneof=theexpected";
                    headers.add(originalCookieHeader);
                    indexOfTheCookieHeader=headers.size()-1;
               }
               else
               {
                   originalCookieHeader = headers.get(indexOfTheCookieHeader);
               }
               String newCookieHeader = originalCookieHeader;
               
               String[] magicParams={
"auth",  "login", "authenticated", "admin", "valid_user", "valid-user", "validuser", "authenticated-user", "authenticated_user", "authenticateduser", "valid", "user", "logged", "loggedin", "logged-in", "logged_in", "login", "administrator", "adminuser", "admin-user", "admin_user", "is_valid", "isvalid", "is-valid", "is_admin", "isadmin", "is-admin", "isauthenticated", "is-authenticated", "is_authenticated", "isuser", "is_user", "is-user", "autologin", "auto-login", "auto_login", "userid", "user_id", "user-id", "signid", "sign_id", "sign-id"
};
               //we add user-defined custom headers, then we append the cookies with the magic list
               String magicParamsWithValues[] = new String[magicParams.length];
               for(int i=0;i<magicParams.length;i++)
               {
                   magicParamsWithValues[i]=magicParams[i]+"=1"; // so far only '1' value
                   // other variants, like 'Y', 'y', 'T', 't' or 'TRUE' could be considered
               }
               String magicCookiesString=String.join("; ", magicParams);
               
               newCookieHeader = newCookieHeader + "; "+magicCookiesString;
               
               headers.set(indexOfTheCookieHeader, newCookieHeader);
               
               // 1. cookies variant
               maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
               maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
               runRequest(maliciousRequest, originalReqResp, "Magic cookies");                
               
               // 2. The query string variant
               // Now, from what we see dealing with helpers' addParameter() is gonna be quite brutal and difficult in general
               // from this point, as well as for other transformations, it seems we're gonna simply 
               // 1. convert our request to a String
               // 2. replace the original element with the new one
               // 3. convert it back to byte and send it out
               // In case of POST/PUT requests we'll also have to make sure that the Content-Length: header contains the valid number.
               
               // rebuild the malicious request with the original cookie header for the query string variant
               headers.set(indexOfTheCookieHeader, originalCookieHeader);
               maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
               String maliciousRequestString = burpCallback.getHelpers().bytesToString(maliciousRequest);
               // and add the magic params to the URL
               // then issue the request
               String magicQueryString=String.join("&",magicParams);
               if(originalReqInfo.getMethod()=="GET")
               {
                   // Several methods here to play with:
                   //String url = originalReqInfo.getUrl().toString();
                   //String path = originalReqInfo.getUrl().getPath(); // this should contain the path info if present
                   //String urlParams = originalReqInfo.getUrl().getQuery();
                   // getUrl().getFile() is the same as getPath(), except it also contains the query string
                   // which is best for our current goal.
                   String urlFile = originalReqInfo.getUrl().getFile(); 
                   // we'll simply append params to it and replace it                   
                   
                   String separator="";
                   if(originalReqInfo.getUrl().getQuery()==null||originalReqInfo.getUrl().getQuery()=="") 
                   {
                       separator="?";
                   }
                   
                   
                   String newUrlFile = urlFile+separator+"&"+magicQueryString;                   
                   
                   maliciousRequestString = maliciousRequestString.replace(urlFile, newUrlFile);
                   
                   maliciousRequest = burpCallback.getHelpers().stringToBytes(maliciousRequestString);
                   
                   runRequest(maliciousRequest, originalReqResp, "Magic query"); 
                   return;
               }               
               if(originalReqInfo.getMethod()=="POST")
               {                   
                   // now, implement POST              
                   String maliciousRequestBodyString  = burpCallback.getHelpers().bytesToString(maliciousRequestBody);
                   maliciousRequestBodyString = maliciousRequestBodyString + "&" + magicQueryString; 
                   maliciousRequestBody = burpCallback.getHelpers().stringToBytes(maliciousRequestBodyString);                   
                   maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);                   
                   runRequest(maliciousRequest, originalReqResp, "Magic query"); 
                   return;
               }
               logOutput("[DEBUG] Query string not supported for "+originalReqInfo.getMethod()+" HTTP method, nothing to do.");
               return;               
            }            
            if(transformation=="http_verbs")
            {
                // so far we'll only try the following method flippings:
                
                // GET -> OPTIONS (got me a shell once :D)
                String reqLine;
                if(originalReqInfo.getMethod()=="GET")
                {
                    // let's try with OPTIONS
                    headers.set(0, headers.get(0).replace("GET", "OPTIONS"));
                    
                    maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
                    maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);                    
                    runRequest(maliciousRequest, originalReqResp, "Method flip");                     
                    headers.set(0, headers.get(0).replace("OPTIONS",originalReqInfo.getMethod())); // restore the original value
                }
                
                // ANY (POST/GET) -> INVLD                                                
                headers.set(0, headers.get(0).replace(originalReqInfo.getMethod(), "INVLD"));
                maliciousRequestBody = Arrays.copyOfRange(originalRawRequest, originalReqInfo.getBodyOffset(), originalRawRequest.length);
                maliciousRequest = burpCallback.getHelpers().buildHttpMessage(headers, maliciousRequestBody);
                runRequest(maliciousRequest, originalReqResp, "Method flip 2");                     
                headers.set(0, headers.get(0).replace("OPTIONS",originalReqInfo.getMethod())); // restore the original value
                return;                
                
                // And what about case mixing in the method :) ?
                // like get and GeT?
            }            
            // So far so good
            /*
            
            // now why not to try some path normalization tricks to try to bypass ACLs
            if(transformation=="path")
            {
                String originalPath = reqInfo.getUrl().getPath();
                // For example, the original path is as follows:
                
                // /admin/manage_user
                // we wanna make the following variations:
                // //admin/manage_user
                // /admin//manage_user
                // /%2fadmin/manage_user
                // //admin/%2fmanage_user                        
                // /admin/../admin
                
                // let's try with these:
                // /admin;foo=bar/?query=string
                // /admin;foo=/bar/?query=string
                // /admin/;foo=bar/?query=string
                // /admin/;foo=/bar/?query=string
            
                // 
                // this: /nuxeo/login.jsp;/..;/[unauthorized_area]
                // is an actual example from https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
                // the only problem with automating this approach here is that we need to extract and confirm some publicly accessible directory from the SiteMap
                // so we can build URIs like:
                // /css/style.css;..;/[original_URI_we_are_testing_against]
                // yeah I believe we can pick this up by simply trying any .css, .js or .png/.jpg file from the site map...
                // or even fucking favicon.ico or robots.txt cause why not ;)
                
                // also on windows I'd try things like:
                // - case mixing
                // - appending the file name with a dot
                // - trying the legacy dos file names
            
                runRequest(maliciousRequest, originalReqResp);
            }
            */

            //logOutput("Unknown transformation '"+transformation+"' (maybe not yet implemented?). Nothing to do.");
        }
        private void runRequest(byte[] maliciousRequest, IHttpRequestResponse originalReqResp, String method)
        {                                 
            IHttpRequestResponse resp = burpCallback.makeHttpRequest(originalReqResp.getHttpService(), maliciousRequest); 
            addResponse(originalReqResp, resp, method);
        }
	//set headerName and newHeader
	private void prepareHeaders() {
			String newHeadersRaw = new String(cookieEditor.getText());

			// Find which HTTP header we are looking for - may not be a cookie
                        String headers[] = newHeadersRaw.split("\n");
                        this.headersToReplace = new String[headers.length];
                        this.namesOfHeadersToReplace = new String[headers.length];
                        for(int i=0;i<headers.length;i++)
                        {
                            //headerName = "cookie:";                            
                            String[] kv = headers[i].split(":", 2);
                            if(kv.length == 2)
                            {
				namesOfHeadersToReplace[i] = kv[0] + ":";
                                headersToReplace[i] = kv[1].replace("\n","").replace("\r","");
                            }   
                        }
	}

	private void runAllRequests(){
		try
                {
			// Clear responses
			clearTable(responseTableModel);

			prepareHeaders();

			for(int i=0; i<requestTable.getRowCount(); i++)
                        {
				runRequests(getRequestObjectByRow(requestTable, i));                		
			}

		} 
                catch(Throwable e)
                {
			PrintWriter writer = new PrintWriter(burpCallback.getStderr());
			writer.write(e.getMessage());
			writer.write("\n");
			e.printStackTrace(writer);
		}
	}
        private void logOutput(String message)
        {
                output.println(message);
        }

	private void addResponse(IHttpRequestResponse originalRequest, IHttpRequestResponse replayedRequest, String method){
		//{"Method", "URL", "Parms","Orig Response Size", "Response Size", "Orig Return Code", "Return Code", "Diff Bytes", "similarity", REQUEST_OBJECT_KEY, RESPONSE_OBJECT_KEY};
		IRequestInfo originalRequestInfo = burpCallback.getHelpers().analyzeRequest(originalRequest);
		IRequestInfo replayedRequestInfo = burpCallback.getHelpers().analyzeRequest(replayedRequest);

		int originalResponseLength;
		byte[] originalResponseBytes;
		short originalResponseStatusCode;
		// When the request has been dropped, the response is null
		if(originalRequest.getResponse() == null){
			originalResponseLength = 0;
			originalResponseBytes = new byte[]{};
			originalResponseStatusCode = -1;
		} else {
			IResponseInfo originalResponseInfo = burpCallback.getHelpers().analyzeResponse(originalRequest.getResponse());
			String originalResponse = new String(originalRequest.getResponse());
			originalResponseLength = BurpApiHelper.getResponseBodyLength(originalResponseInfo, originalRequest.getResponse());
			originalResponseBytes = originalResponse.substring(originalResponseInfo.getBodyOffset()).getBytes();
			originalResponseStatusCode = originalResponseInfo.getStatusCode();
		}
		IResponseInfo replayedResponseInfo = burpCallback.getHelpers().analyzeResponse(replayedRequest.getResponse());

		int diff = -1;
		int similarity = -1;

		String replayedResponse = new String(replayedRequest.getResponse());

		int replayedResponseLength = BurpApiHelper.getResponseBodyLength(replayedResponseInfo, replayedRequest.getResponse());

		try{

			
			//								 replayedResponse.substring(replayedResponseInfo.getBodyOffset()).getBytes());
			//diff = diffb.length;
                        diff = 1337;
			double total = originalResponseLength + replayedResponseLength;
			double percent = (1.0-((diff*2)/total))*100.0;
			similarity = (int)percent;
			if(similarity > 100){
				similarity = 100;
			} else if(similarity < 0){
				similarity = 0;
			}

		} catch (Exception e) {
			PrintWriter writer = new PrintWriter(burpCallback.getStderr());
			writer.write(e.getMessage());
			writer.write("\n");
			e.printStackTrace(writer);
		}

		int idx = responseTable.getRowCount() + 1; // 1-indexed

		responseTableModel.addRow(new Object[]{
			  idx,
				replayedRequestInfo.getMethod(), 
				originalRequestInfo.getUrl(), 
				method, 
				originalResponseLength,
				replayedResponseLength,
				originalResponseStatusCode,
				replayedResponseInfo.getStatusCode(),
				diff,
				similarity,
				originalRequest, 
				replayedRequest
		});

	}

	private void clearTable(DefaultTableModel model){
		model.getDataVector().removeAllElements();
		model.fireTableDataChanged();
	}

	public IHttpRequestResponse getRequestObjectByRow(JTable table, int row) {
		return getRequestObjectByModelIndex( (DefaultTableModel)table.getModel(), table.convertRowIndexToModel(row) );
	}

	public IHttpRequestResponse getResponseObjectByRow(JTable table, int row) {
		return getResponseObjectByModelIndex( (DefaultTableModel)table.getModel(), table.convertRowIndexToModel(row) );
	}

	public IHttpRequestResponse getRequestObjectByModelIndex(DefaultTableModel model, int index){
		return (IHttpRequestResponse)model.getValueAt(index, model.findColumn(REQUEST_OBJECT_KEY));
	}

	public IHttpRequestResponse getResponseObjectByModelIndex(DefaultTableModel model, int index){
		return (IHttpRequestResponse)model.getValueAt(index, model.findColumn(RESPONSE_OBJECT_KEY));
	}

	private int reqIdx = 0; //have to store this, as we can delete from req table, and don't want to reuse numbers.
	public void addRequests(IHttpRequestResponse requestResponse[]){
		for(IHttpRequestResponse rr: requestResponse) {

			IRequestInfo info = burpCallback.getHelpers().analyzeRequest(rr);
			// The response may be null if being sent from the proxy, prior to a drop
			//{"Method", "URL", "Parms", "Response Code", REQUEST_OBJECT_KEY}
			IHttpRequestResponsePersisted rrp = burpCallback.saveBuffersToTempFiles(rr);

			String sc;
			if(rr.getResponse() != null){
				sc = Short.toString(burpCallback.getHelpers().analyzeResponse(rr.getResponse()).getStatusCode());
			} else {
				sc = "n/a";
			}

			requestTableModel.addRow(new Object[]{
				++reqIdx,
				info.getMethod(), 
				info.getUrl(),
				(info.getParameters().size() > 0),
				sc,
				rrp
			});
		}
	}

	private static void addPopup(Component component, final JPopupMenu popup) {
		component.addMouseListener(new MouseAdapter() {
			public void mousePressed(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			public void mouseReleased(MouseEvent e) {
				if (e.isPopupTrigger()) {
					showMenu(e);
				}
			}
			private void showMenu(MouseEvent e) {
				popup.show(e.getComponent(), e.getX(), e.getY());
			}
		});
	}


}
