VERSION 5.00
Object = "{248DD890-BB45-11CF-9ABC-0080C7E7B78D}#1.0#0"; "MSWINSCK.OCX"
Begin VB.Form Form1 
   BorderStyle     =   1  'Fixed Single
   Caption         =   "Secure Socket Layer Client Example"
   ClientHeight    =   6000
   ClientLeft      =   45
   ClientTop       =   330
   ClientWidth     =   7935
   LinkTopic       =   "Form1"
   MaxButton       =   0   'False
   ScaleHeight     =   6000
   ScaleWidth      =   7935
   StartUpPosition =   3  'Windows Default
   Begin VB.TextBox Text3 
      Height          =   375
      Left            =   2040
      TabIndex        =   4
      Text            =   "www.paypal.com"
      Top             =   5280
      Width           =   2175
   End
   Begin MSWinsockLib.Winsock Winsock1 
      Left            =   240
      Top             =   240
      _ExtentX        =   741
      _ExtentY        =   741
      _Version        =   393216
   End
   Begin VB.CommandButton Command2 
      Caption         =   "Send Data"
      Height          =   375
      Left            =   6120
      TabIndex        =   3
      Top             =   4560
      Width           =   1695
   End
   Begin VB.TextBox Text2 
      Height          =   375
      Left            =   120
      TabIndex        =   2
      Text            =   "GET https://www.paypal.com/"
      Top             =   4560
      Width           =   5895
   End
   Begin VB.TextBox Text1 
      Height          =   4335
      Left            =   120
      Locked          =   -1  'True
      MultiLine       =   -1  'True
      ScrollBars      =   2  'Vertical
      TabIndex        =   1
      Top             =   120
      Width           =   7695
   End
   Begin VB.CommandButton Command1 
      Caption         =   "Connect to Server"
      Default         =   -1  'True
      Height          =   615
      Left            =   120
      TabIndex        =   0
      Top             =   5160
      Width           =   1815
   End
End
Attribute VB_Name = "Form1"
Attribute VB_GlobalNameSpace = False
Attribute VB_Creatable = False
Attribute VB_PredeclaredId = True
Attribute VB_Exposed = False
'This is my first ever submission to Planet Source Code.  I have
'found PSC extremely useful to me over the years, and wanted to give
'back to the community.  Thanks to all the other generous coders
'out there.  This example shows how the Secure Socket Layer (SSL)
'version 2.0 protocol works.  After looking all over the Internet
'for a VB example of this I soon realized that there were no such
'examples and would have to create my own implemention of it.  It is
'compatible with any SSL server; to see an example, click the
'"Connect to Server" button, and after it says connected click
'"Send Data".  This should retrieve PayPal's HTML and display it in
'the text box.  However, it used HTTPS or the secure version of
'HTTP to get it. :-)
'
'SSL is based on public key cryptography, it works in the following manner:
'
'client-hello         C -> S: challenge, cipher_specs
'server-hello         S -> C: connection-id,server_certificate,cipher_specs
'client-master-key    C -> S: {master_key}server_public_key
'client-finish        C -> S: {connection-id}client_write_key
'server-verify        S -> C: {challenge}server_write_key
'server-finish        S -> C: {new_session_id}server_write_key
'
'First the Client sends some random data known as the CHALLENGE, along with a list of ciphers it can use, for simplicity we will only use 128-bit RC4 with MD5
'The Server responds with a random data, known as the CONNECTION-ID, and the Server's Certificate and list of cipher specs
'The Client extracts the Public Key from the Server's Certificate then uses it to Encrypt a randomly generated Master Key, this Key then sent to the Server
'The Client and Server both generate 2 keys each by hashing the Master Key with other values, and the client sends a finish message, encrypted with the client write key
'The Server Responds by returning the CHALLENGE encrypted using the Client Read Key, this proves to the Clinet that the Server is who it says its is
'The Server sends its finish message, which consists of a randomly generated value, this value can be used to re-create the session in a new connection, but that is not supported in this example
'
'For a more detailed explaination of the protocol, please see: http://colossus.net/SSL.html
'To visit my website, and check out my communications service created in Visual Basic, go to http://www.gcn.cx/
'If you need to e-mail me you can try contacting me at jason@gcn.cx, but take notice I don't check my box very often
'
'Oh, and you are free to use this code in any of your commerical or non-commercial applications, but if you redistribute this source code I ask that you preserve these comments.
'
'Thank you, and enjoy.

' Thanks to Seth Taylor and Anonymous who posted on 12/8/2004 8:16:37 PM
' For their bug reports!

Option Explicit

Private Sub Command2_Click()

    'Send Encrypted Record if Ready
    If Layer = 3 Then
        Call SSLSend(Winsock1, Text2.Text & vbCrLf)
        Text2.Text = ""
    End If

End Sub



Private Sub Text3_Change()

    'Update Text2.Text to match the hostname
    Text2.Text = "GET https://" & Text3.Text & "/"

End Sub


' Modified by Seth Taylor 2005-02-22 to buffer incoming data and process appropriately
Private Sub Winsock1_DataArrival(ByVal bytesTotal As Long)
    Dim TheData As String
    Dim Response As String
    Response = ""
    
    ' Buffer incoming data while connection is open or being opened
    If Layer < 4 Then
        Call Winsock1.GetData(TheData, vbString, bytesTotal)
        DataBuffer = DataBuffer & TheData
    End If
    
    If Layer = 3 Then
        ' Download complete response before processing
        Exit Sub
    End If
    
    'Parse each SSL Record
    Do
    
        If SeekLen = 0 Then
            If Len(DataBuffer) >= 2 Then
                TheData = GetBufferDataPart(2)
                SeekLen = BytesToLen(TheData)
            Else
                Exit Sub
            End If
        End If
        
        If Len(DataBuffer) >= SeekLen Then
            TheData = GetBufferDataPart(SeekLen)
        Else
            Exit Sub
        End If
        
        
        Select Case Layer
            Case 0:
                ENCODED_CERT = Mid(TheData, 12, BytesToLen(Mid(TheData, 6, 2)))
                CONNECTION_ID = Right(TheData, BytesToLen(Mid(TheData, 10, 2)))
                Call IncrementRecv
                Call SendMasterKey(Winsock1)
            Case 1:
                TheData = SecureSession.RC4_Decrypt(TheData)
                If Right(TheData, Len(CHALLENGE_DATA)) = CHALLENGE_DATA Then
                    If VerifyMAC(TheData) Then
                        Call SendClientFinish(Winsock1)
                    Else
                        ' SSL Error -- send SSL error to server
                        MsgBox ("SSL Error: Invalid MAC data ... aborting connection.")
                        Winsock1.Close
                    End If
                Else
                    ' SSL Error -- send SSL error to server
                    MsgBox ("SSL Error: Invalid Challenge data ... aborting connection.")
                    Winsock1.Close
                End If
             Case 2:
                TheData = SecureSession.RC4_Decrypt(TheData)
                If VerifyMAC(TheData) = False Then
                    ' SSL Error -- send SSL error to server
                    MsgBox ("SSL Error: Invalid MAC data ... aborting connection.")
                    Winsock1.Close
                End If
                Layer = 3
             Case 3:
                ' Do nothing while buffer is filled ... wait for connection to close
             Case 4:
                TheData = SecureSession.RC4_Decrypt(TheData)
                If VerifyMAC(TheData) Then
                    Response = Response & Mid(TheData, 17)
                Else
                    ' SSL Error -- data is corrupt and must be discarded
                    MsgBox ("SSL Error: Invalid MAC data ... Data discarded.")
                    Layer = 0
                    DataBuffer = ""
                    Response = ""
                    Exit Sub
                End If
        End Select
    
        SeekLen = 0

    Loop Until Len(DataBuffer) = 0
    
    If Layer = 4 Then
        Layer = 0
        Call ProcessData(Response)
    End If

End Sub

' This function added by Seth Taylor 2005-02-22 to get data from DataBuffer
Function GetBufferDataPart(ByVal Length As Long) As String
    Dim L As Long
    L = Len(DataBuffer)
    If Length > L Then
        ' Error ... ?
        Length = L
        GetBufferDataPart = Left(DataBuffer, L)
    Else
        GetBufferDataPart = Left(DataBuffer, Length)
    End If
    If Length = L Then
        DataBuffer = ""
    Else
        DataBuffer = Mid(DataBuffer, Length + 1)
    End If
End Function


Public Sub Command1_Click()

    'Open Socket to Remote Server
    Winsock1.Close
    Winsock1.Connect Text3.Text, 443

End Sub


Public Sub Winsock1_Close()

    'Close Socket
    Me.Caption = "Closed."
    Winsock1.Close
    
    'Process downloaded information
    If Layer = 3 Then
        Layer = 4
        Call Winsock1_DataArrival(0)
    End If
    Layer = 0
    
    Set SecureSession = Nothing

End Sub

Private Sub Winsock1_Connect()

    'Send Client Hello
    Me.Caption = "Connected"
    Processing = False
    Set SecureSession = New CryptoCls
    Call SendClientHello(Winsock1)

End Sub

Private Sub Winsock1_Error(ByVal Number As Integer, Description As String, ByVal Scode As Long, ByVal Source As String, ByVal HelpFile As String, ByVal HelpContext As Long, CancelDisplay As Boolean)

    MsgBox ("Winsock Error: (" & Number & ") " & Description)
    
    'Call Close Sub
    Winsock1_Close

End Sub
