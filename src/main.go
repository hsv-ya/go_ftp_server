/*
 * ACTIVE FTP SERVER Start-up Code (WinSock 2) simple rewrite on Rust
 *
 * This code gives parts of the answers away.
 * The sample TCP server codes will help you accomplish this.
 *
 * OVERVIEW
 * Only the active FTP mode connection is implemented (watch out for firewall
 * issues - do not block your own FTP server!).
 *
 * Only IP4
 *
 * The ftp LIST command is fully implemented, in a very naive way using
 * redirection and a temporary file.
 */
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var MONTHS = [...]string{
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

const SYSTEM_COMMAND_DEL = "del"
const SYSTEM_COMMAND_MKDIR = "mkdir"
const SYSTEM_COMMAND_RMDIR = "rmdir"
const SYSTEM_COMMAND_RENAME = "rename"

var SHOW_DEBUG_MESSAGE bool
var CONVERT_CYRILLIC bool

const DEFAULT_PORT = "21"
const BIG_BUFFER_SIZE uint = 65535

type TcpStream = net.Conn

// Arguments:
//
//	0:  Program name
//	1:  Port number
//	2:  Debug mode (true/false)
//	3:  Use convert cyrillic file and directory name between Android and Windows 7 (true/false)
func main() {
	set_debug(debug_mode())

	set_convert_cyrillic(convert_cyrillic())

	var env_temp = get_temp_directory()

	if len(env_temp) == 0 {
		panic("Error, not find environment <TEMP>!!")
	} else if len(env_temp) > 50 {
		panic("Error, very long size for environment <TEMP>!!")
	}

	var port = get_server_address_info()

	listener, err := net.Listen("tcp4", port)

	if err != nil {
		panic(err)
	}

	defer listener.Close()

	show_server_info()

	for {
		conn, err := listener.Accept()

		if err != nil {
			fmt.Println(err)
			conn.Close()
			continue
		}

		go handle_clients(conn)
	}
}

func set_debug(b bool) {
	SHOW_DEBUG_MESSAGE = b
}

func is_debug() bool {
	return SHOW_DEBUG_MESSAGE
}

// Returns true if user indicated that debug mode should be on.
func debug_mode() bool {
	if len(os.Args) > 2 {
		if os.Args[2] == "true" {
			return true
		}
	}

	return false
}

func set_convert_cyrillic(b bool) {
	CONVERT_CYRILLIC = b
}

func is_convert_cyrillic() bool {
	return CONVERT_CYRILLIC
}

// Returns true if user indicated that convert cyrillic should be on.
func convert_cyrillic() bool {
	if len(os.Args) > 3 {
		if os.Args[3] == "true" {
			return true
		}
	}

	return false
}

func show_server_info() {
	fmt.Println("===============================")
	fmt.Println("     159.334 FTP Server        ")
	fmt.Println("===============================")
}

// Gets the servers address information based on arguments.
func get_server_address_info() string {
	var result string
	if len(os.Args) > 1 {
		result = fmt.Sprintf(":%s", os.Args[1])
	} else {
		result = fmt.Sprintf(":%s", DEFAULT_PORT)
	}
	return result
}

// Accepts new clients and deals with commands.
func handle_clients(s TcpStream) {
	show_client_info(s)

	if !send_message(s, "220 FTP Server ready.\r\n") {
		close_client_connection(s)
		return
	}

	var success = true
	var authroised_login = false
	var connect_to string
	var client_id int = get_client_port(s)
	var current_directory string
	var name_file_or_dir_for_rename string

	for success {
		success = communicate_with_client(
			s,
			&connect_to,
			&authroised_login,
			client_id,
			&current_directory,
			&name_file_or_dir_for_rename)
	}

	close_client_connection(s)
}

func get_client_port(s TcpStream) int {
	tmp := strings.Split(s.RemoteAddr().String(), ":")[1]
	value, err := strconv.ParseInt(tmp, 10, 64)
	if err != nil {
		fmt.Println(err)
		return 0
	}
	return int(value)
}

// Takes incoming connection and assigns new socket.
func show_client_info(s TcpStream) {
	fmt.Println("A client has been accepted.")

	addr := strings.Split(s.RemoteAddr().String(), ":")

	fmt.Printf("Connected to client with IP address: %s, at Port: %s\n", addr[0], addr[1])
}

// Receive and handle messages from client, returns false if client ends connection.
func communicate_with_client(s TcpStream, connect_to *string, authroised_login *bool, client_id int, current_directory *string, name_file_or_dir_for_rename *string) bool {
	var receive_buffer []byte
	var user_name string
	var password string

	var receipt_successful = receive_message(s, &receive_buffer)
	if !receipt_successful {
		return receipt_successful
	}

	var success bool

	var maybe_command string = string(receive_buffer[:4])

	switch maybe_command {
	case "USER":
		{
			var i_attempts = 0

			for {
				success = command_user_name(s, receive_buffer, user_name, authroised_login)

				if !success {
					i_attempts++

					receipt_successful = receive_message(s, &receive_buffer)
					if !receipt_successful {
						return receipt_successful
					}
				}
				if success || i_attempts >= 3 {
					break
				}
			}
			return success
		}

	case "PASS":
		success = command_password(s, receive_buffer, password, authroised_login)
	case "SYST":
		success = command_system_information(s)
	case "QUIT":
		success = command_quit()
	case "PORT":
		success = command_port(s, connect_to, receive_buffer)
	case "LIST", "NLST":
		success = command_list(s, *connect_to, client_id, *current_directory)
	case "RETR":
		success = command_retrieve(s, *connect_to, receive_buffer, *current_directory)
	case "STOR":
		success = command_store(s, *connect_to, receive_buffer, *current_directory)
	case "CWD ":
		success = command_change_working_directory(s, receive_buffer, current_directory)
	case "DELE":
		success = command_delete(s, receive_buffer)
	case "MKD ":
		success = command_make_directory(s, receive_buffer)
	case "RMD ":
		success = command_delete_directory(s, receive_buffer)
	case "TYPE":
		success = command_type(s, receive_buffer)
	case "FEAT":
		success = command_feat(s)
	case "OPTS":
		success = command_opts(s, receive_buffer)
	case "RNFR":
		success = command_rename_from(s, receive_buffer, name_file_or_dir_for_rename)
	case "RNTO":
		success = command_rename_to(s, receive_buffer, name_file_or_dir_for_rename)
	case "MFMT":
		success = command_mfmt(s, receive_buffer)
	default:
		success = command_unknown(s)
	}

	return success
}

// Receives message and saves it in receive buffer, returns false if connection ended.
func receive_message(s TcpStream, receive_buffer *[]byte) bool {
	var bytes int
	var buffer = make([]byte, 1)
	var err error

	*receive_buffer = make([]byte, 0)

	for {
		bytes, err = s.Read(buffer)

		if err != nil {
			fmt.Println("Read error:", err)
			bytes = 0
			break
		}

		if bytes == 0 {
			break
		}

		if buffer[0] == '\n' {
			break
		} else if buffer[0] == '\r' {
			continue
		}

		*receive_buffer = append(*receive_buffer, buffer[:1]...)
	}

	if bytes == 0 {
		return false
	}

	if is_debug() {
		fmt.Printf("<--- %s\n", string(*receive_buffer))
	}

	return true
}

// Client sent USER command, returns false if fails.
func command_user_name(s TcpStream, receive_buffer []byte, user_name string, authroised_login *bool) bool {
	remove_command(receive_buffer, &user_name, 4)

	fmt.Printf("User: \"%s\" attempting to login.\n", user_name)

	*authroised_login = is_valid_user_name(user_name)

	if *authroised_login {
		fmt.Println("User name valid. Password required.")

		return send_message(s, "331 Authorised login requested, please specify the password.\r\n")
	} else {
		fmt.Println("User name unauthorised. Public access only.")

		return send_message(s, "331 Public login requested, please specify email as password.\r\n")
	}
}

// Send message to client, returns true if message was sended.
func send_message(s TcpStream, send_buffer string) bool {
	var bytes = len(send_buffer)
	n, err := s.Write([]byte(send_buffer))
	if err != nil {
		fmt.Println(err)
		return false
	}
	if is_debug() {
		fmt.Printf("---> %s", send_buffer)
	}
	return bytes == n
}

// Returns true if valid user name.
func is_valid_user_name(user_name string) bool {
	return user_name == "nhreyes"
}

// Client sent PASS command, returns false if fails.
func command_password(s TcpStream, receive_buffer []byte, password string, authroised_login *bool) bool {
	remove_command(receive_buffer, &password, 4)

	var valid_password = is_valid_password(password, authroised_login)

	var send_buffer string

	if valid_password {
		fmt.Println("Password valid. User logged in.")

		send_buffer = "230 Login successful.\r\n"
	} else {
		fmt.Println("Password invalid. Login failed.")

		send_buffer = "530 Login authentication failed.\r\n"
	}

	if !send_message(s, send_buffer) {
		return false
	}

	return valid_password
}

// Returns true if valid password.
func is_valid_password(password string, authroised_login *bool) bool {
	if *authroised_login {
		return password == "334"
	} else {
		return is_email_address(password)
	}
}

// Client sent SYST command, returns false if fails.
func command_system_information(s TcpStream) bool {
	fmt.Println("System information requested.")

	return send_message(s, "215 Windows Type: WIN64\r\n")
}

// Client sent QUIT command, returns false if fails.
func command_quit() bool {
	fmt.Println("Client has quit the session.")

	return false
}

// Client sent PORT command, returns false if fails.
func command_port(s TcpStream, connect_to *string, receive_buffer []byte) bool {
	fmt.Println("===================================================")
	fmt.Println("\tActive FTP mode, the client is listening...")

	*connect_to = get_client_ip_and_port(receive_buffer)

	if len(*connect_to) == 0 {
		return send_argument_syntax_error(s)
	} else {
		return send_message(s, "200 PORT Command successful.\r\n")
	}
}

// Gets the client's IP and port number for active connection.
func get_client_ip_and_port(receive_buffer []byte) string {
	var parts []string = strings.Split(string(receive_buffer[5:]), ",")

	if cap(parts) != 6 {
		return ""
	}

	if is_debug() {
		fmt.Println(parts)
	}

	var active_ip []string = parts[:4]

	if is_debug() {
		fmt.Println(active_ip)
	}

	var active_port []int = make([]int, 2)

	var value int64
	var err error

	value, err = strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	active_port[0] = int(value)

	value, err = strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	active_port[1] = int(value)

	if is_debug() {
		fmt.Println(active_port)
	}

	var ip_buffer = fmt.Sprintf("%s.%s.%s.%s", active_ip[0], active_ip[1], active_ip[2], active_ip[3])
	fmt.Printf("\tClient's IP is %s\n", ip_buffer)

	var port_decimal int = active_port[0]<<8 | active_port[1]
	var port_buffer = strconv.Itoa(port_decimal)
	fmt.Printf("\tClient's Port is %s\n", port_buffer)

	return ip_buffer + ":" + port_buffer
}

func send_argument_syntax_error(s TcpStream) bool {
	return send_message(s, "501 Syntax error in arguments.\r\n")
}

// Sends the client a message to say data connection failed.
func send_failed_active_connection(s TcpStream) bool {
	return send_message(s, "425 Something is wrong, can't start active connection.\r\n")
}

// Client sent LIST command, returns false if fails.
func command_list(s TcpStream, connect_to string, client_id int, current_directory string) bool {
	var path_temp = get_temp_directory()

	var tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", path_temp, client_id)

	var result = send_file(s, connect_to, tmp, client_id, current_directory)

	if result != 1 {
		return false
	}

	return send_message(s, "226 Directory send OK.\r\n")
}

func get_temp_directory() string {
	return os.Getenv("TEMP")
}

func delete_temp_files(file1, file2, file3 string) {
	execute_system_command(SYSTEM_COMMAND_DEL, file1)
	execute_system_command(SYSTEM_COMMAND_DEL, file2)
	execute_system_command(SYSTEM_COMMAND_DEL, file3)
}

// Sends specified file to client, return '1' if not have error.
func send_file(s TcpStream, connect_to string, file_name string, client_id int, current_directory string) int {
	var tmp string
	var tmp_directory string
	var tmp_file string
	var tmp_dir_directory = "dir /A:D /B"
	var tmp_dir_files = "dir /A:-D /-C"

	if client_id > 0 {
		fmt.Println("Client has requested the directory listing.")

		year := int64(time.Now().Year())

		var path_temp = get_temp_directory()

		tmp = fmt.Sprintf("%s\\%d_tmp_dir.txt", path_temp, client_id)
		tmp_directory = fmt.Sprintf("%s\\%d_tmp_dir2.txt", path_temp, client_id)
		tmp_file = fmt.Sprintf("%s\\%d_tmp_dir3.txt", path_temp, client_id)

		tmp_dir_directory += " >"
		tmp_dir_directory += tmp_directory

		tmp_dir_files += " >"
		tmp_dir_files += tmp_file

		if is_debug() {
			fmt.Printf("<<<DEBUG INFO>>>: %v %v\n", tmp_dir_files, current_directory)
		}

		execute_system_command(tmp_dir_files, current_directory)

		if is_debug() {
			fmt.Printf("<<<DEBUG INFO>>>: %v %v\n", tmp_dir_directory, current_directory)
		}

		execute_system_command(tmp_dir_directory, current_directory)

		f_dir, err := os.Create(tmp)
		if err != nil {
			fmt.Println(err)
			return 0
		}

		f_directory, err := os.Open(tmp_directory)
		if err != nil {
			fmt.Println(err)
			f_dir.Close()
			f_directory.Close()
			return 0
		}

		var is_first = true

		var buffer []byte
		var buffer_for_read = make([]byte, 1)
		var n int

		for {
			n, err = f_directory.Read(buffer_for_read)
			if err == io.EOF {
				break
			}
			if n != 1 || err != nil {
				fmt.Println(err)
				break
			}
			var b byte = buffer_for_read[0]
			if b == '\r' {
				continue
			} else if b == '\n' {
				var tmp_buffer_dir = "drw-rw-rw-    1 user       group        512 Oct 15  2024 "
				if !is_convert_cyrillic() {
					var line = string(buffer)
					tmp_buffer_dir += line
				} else {
					var tmp_new_file_name []byte
					simple_conv(buffer, &tmp_new_file_name, false)
					var str_tmp_new_file_name = string(tmp_new_file_name)
					tmp_buffer_dir += str_tmp_new_file_name
				}
				if !is_first {
					f_dir.Write([]byte("\n"))
				} else {
					is_first = false
				}
				f_dir.Write([]byte(tmp_buffer_dir))
				if is_debug() {
					fmt.Println(tmp_buffer_dir)
				}
				buffer = buffer[:0]
			} else {
				buffer = append(buffer, b)
			}
		}

		f_directory.Close()

		buffer = buffer[:0]

		var f_files *os.File
		f_files, err = os.Open(tmp_file)
		if err != nil {
			fmt.Println(err)
			f_dir.Close()
			f_files.Close()
			return 0
		}

		var skip_lines = 5
		var tmp_file_name string
		var tmp_buffer_file string

		for {
			n, err = f_files.Read(buffer_for_read)
			if err == io.EOF {
				break
			}
			if n != 1 || err != nil {
				fmt.Println(err)
				break
			}
			var b byte = buffer_for_read[0]
			if b == '\r' {
				continue
			} else if b == '\n' {
				if skip_lines > 0 {
					skip_lines -= 1
					buffer = buffer[:0]
					continue
				}

				if is_numerical(buffer[0]) {
					var line = string(buffer[0:36])

					var line_for_split string = line
					for strings.Contains(line_for_split, "  ") {
						line_for_split = strings.ReplaceAll(line_for_split, "  ", " ")
					}

					var v []string = strings.Split(line_for_split, " ")
					var tmp_date = []byte(v[0])

					var i_day, i_month, i_year int64
					i_day, err = strconv.ParseInt(string(tmp_date[0:2]), 10, 8)
					i_month, err = strconv.ParseInt(string(tmp_date[3:5]), 10, 8)
					i_year, err = strconv.ParseInt(string(tmp_date[6:10]), 10, 64)

					var tmp_time = []byte(v[1])
					var i_hour, i_minute int64
					i_hour, err = strconv.ParseInt(string(tmp_time[0:2]), 10, 8)
					i_minute, err = strconv.ParseInt(string(tmp_time[3:5]), 10, 8)

					var tmp_file_size = v[2]

					var file_size int64
					file_size, err = strconv.ParseInt(tmp_file_size, 10, 64)

					var tmp_file_name_vec []byte = buffer[36:]

					if year == i_year {
						tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d %02d:%02d ", file_size, MONTHS[i_month-1], i_day, i_hour, i_minute)
					} else {
						tmp_buffer_file = fmt.Sprintf("-rw-rw-rw-    1 user       group %10d %s %02d  %04d ", file_size, MONTHS[i_month-1], i_day, i_year)
					}
					if !is_convert_cyrillic() {
						tmp_file_name = string(buffer[36:])
						tmp_buffer_file += tmp_file_name
					} else {
						var tmp_new_file_name_vec []byte
						simple_conv(tmp_file_name_vec, &tmp_new_file_name_vec, false)
						var tmp_new_file_name = string(tmp_new_file_name_vec)
						tmp_buffer_file += tmp_new_file_name
					}
					if !is_first {
						f_dir.Write([]byte("\n"))
					} else {
						is_first = false
					}
					f_dir.Write([]byte(tmp_buffer_file))
					if is_debug() {
						fmt.Println(tmp_buffer_file)
					}
				}
				buffer = buffer[:0]
			} else {
				buffer = append(buffer, b)
			}
		}

		f_dir.Write([]byte("\n"))

		f_files.Close()
		f_dir.Close()
	} else {
		fmt.Printf("Client has requested to retrieve the file: \"%s\".", file_name)
	}

	var file_name_for_open string

	if client_id > 0 {
		file_name_for_open = tmp
	} else {
		file_name_for_open = current_directory

		if len(file_name_for_open) > 0 {
			file_name_for_open += "\\"
		}

		file_name_for_open += file_name
	}

	var f_in, err = os.OpenFile(file_name_for_open, os.O_RDONLY, 0666)
	defer f_in.Close()
	if err != nil {
		fmt.Println("Error:", err)

		if !send_message(s, "550 File name invalid.\r\n") {
			return 0
		}

		return -1
	} else {
		if !send_message(s, "150 Data connection ready.\r\n") {
			if client_id > 0 {
				if !is_debug() {
					delete_temp_files(tmp, tmp_directory, tmp_file)
				}
			}

			return 0
		}
	}

	send_to, err := net.Dial("tcp", connect_to)
	defer send_to.Close()
	if err != nil {
		fmt.Println(err)
		if client_id > 0 {
			if !is_debug() {
				delete_temp_files(tmp, tmp_directory, tmp_file)
			}
		}
		return 0
	}

	var temp_buffer []byte = make([]byte, BIG_BUFFER_SIZE)

	for {
		var result, err = f_in.Read(temp_buffer)
		if err == io.EOF {
			break
		}

		var read_bytes int

		if err != nil {
			fmt.Println(err)
			return 0
		}

		read_bytes = result

		if read_bytes == 0 {
			break
		}

		var bytes int
		bytes, err = send_to.Write(temp_buffer[:read_bytes])
		if err != nil {
			fmt.Println(err)
			return 0
		}

		if bytes != read_bytes {
			if client_id > 0 {
				if !is_debug() {
					delete_temp_files(tmp, tmp_directory, tmp_file)
				}
			}
			return 0
		}
	}

	if client_id > 0 {
		if !is_debug() {
			delete_temp_files(tmp, tmp_directory, tmp_file)
		}
	}

	fmt.Println("File sent successfully.")

	return 1
}

// return '0' if not have error.
func execute_system_command(args ...string) int {
	if is_debug() {
		fmt.Printf("Execute command: %s\n", args)
	}

	var cmd_args []string = make([]string, 1)
	cmd_args[0] = "/C"
	for _, arg := range args {
		cmd_args = append(cmd_args, arg)
	}
	if err := exec.Command("cmd", cmd_args...).Run(); err != nil {
		fmt.Println("Error:", err)
	}

	return 0
}

// Client sent RETR command, returns false if fails.
func command_retrieve(s TcpStream, connect_to string, receive_buffer []byte, current_directory string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	var result = send_file(s, connect_to, tmp, 0, current_directory)

	if result == 1 {
		return false
	}

	return send_message(s, "226 File transfer complete.\r\n")
}

// Client sent STORE command, returns false if fails.
func command_store(s TcpStream, connect_to string, receive_buffer []byte, current_directory string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	var result = save_file(s, connect_to, tmp, current_directory)

	if !result {
		return result
	}

	return send_message(s, "226 File transfer complete.\r\n")
}

// Sends specified file to client.
func save_file(s TcpStream, connect_to, file_name, current_directory string) bool {
	fmt.Printf("Client has requested to store the file: \"%s\".\n", file_name)

	recv_from, err := net.Dial("tcp", connect_to)
	defer recv_from.Close()
	if err != nil {
		fmt.Println(err)
		send_failed_active_connection(s)
		return false
	}

	if !send_message(s, "150 Data connection ready.\r\n") {
		return false
	}

	var file_name_full = current_directory

	if len(file_name_full) > 0 {
		file_name_full += "\\"
	}

	file_name_full += file_name

	var f_out_file *os.File
	f_out_file, err = os.Create(file_name_full)
	defer f_out_file.Close()
	if err != nil {
		fmt.Println(err)
		return false
	}

	var temp_buffer []byte = make([]byte, BIG_BUFFER_SIZE)

	for {
		var recv_bytes, err = recv_from.Read(temp_buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println(err)
			return false
		}

		if recv_bytes > 0 {
			if n, err := f_out_file.Write(temp_buffer[:recv_bytes]); n == 0 || err != nil {
				fmt.Println(err)
				return false
			}
		}
	}

	fmt.Println("File saved successfully.")

	return true
}

// Client sent CWD command, returns false if connection ended.
func command_change_working_directory(s TcpStream, receive_buffer []byte, current_directory *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	*current_directory = tmp

	if *current_directory == "\\" {
		*current_directory = ""
	}

	return send_message(s, "250 Directory successfully changed.\r\n")
}

// Client sent DELETE command, returns false if connection ended.
func command_delete(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_DEL, tmp)

	if is_debug() {
		fmt.Printf("<<<DEBUG INFO>>>: %s %s\n", SYSTEM_COMMAND_DEL, tmp)
	}

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent MKD command, returns false if connection ended.
func command_make_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_MKDIR, tmp)

	if is_debug() {
		fmt.Printf("<<<DEBUG INFO>>>: %s %s\n", SYSTEM_COMMAND_MKDIR, tmp)
	}

	var send_buffer = fmt.Sprintf("257 '/%s' directory created\r\n", tmp)

	return send_message(s, send_buffer)
}

// Client sent RMD command, returns false if connection ended.
func command_delete_directory(s TcpStream, receive_buffer []byte) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 4)

	replace_backslash(&tmp)

	execute_system_command(SYSTEM_COMMAND_RMDIR, tmp)

	if is_debug() {
		fmt.Printf("<<<DEBUG INFO>>>: %s %s\n", SYSTEM_COMMAND_RMDIR, tmp)
	}

	return send_message(s, "250 Requested file action okay, completed.\r\n")
}

// Client sent TYPE command, returns false if connection ended.
func command_type(s TcpStream, receive_buffer []byte) bool {
	var type_name string

	remove_command(receive_buffer, &type_name, 4)

	var send_buffer = fmt.Sprintf("200 Type set to %s.\r\n", type_name)

	return send_message(s, send_buffer)
}

// Client sent FEAT command, returns false if fails.
func command_feat(s TcpStream) bool {
	return send_message(s, "211-Extensions supported\r\n UTF8\r\n MFMT\r\n211 end\r\n")
}

// Client sent OPTS command, returns false if connection ended.
func command_opts(s TcpStream, receive_buffer []byte) bool {
	var opts_name string

	remove_command(receive_buffer, &opts_name, 4)

	if opts_name == "UTF8 ON" {
		return send_message(s, "200 UTF8 ON.\r\n")
	} else {
		return send_argument_syntax_error(s)
	}
}

// Client sent RNFR command, returns false if connection ended.
func command_rename_from(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	*name_file_or_dir_for_rename = tmp

	return send_message(s, "350 Requested file action pending further information.\r\n")
}

// Client sent RNTO command, returns false if connection ended.
func command_rename_to(s TcpStream, receive_buffer []byte, name_file_or_dir_for_rename *string) bool {
	var tmp string

	remove_command(receive_buffer, &tmp, 5)

	replace_backslash(&tmp)

	var name_file_or_dir_to_rename = tmp

	if 0 == len(*name_file_or_dir_for_rename) || 0 == len(name_file_or_dir_to_rename) {
		*name_file_or_dir_for_rename = ""

		return send_message(s, "503 Bad sequence of commands.\r\n")
	}

	var v []string = strings.Split(name_file_or_dir_to_rename, "\\")

	var name = v[cap(v)]

	var result = execute_system_command(SYSTEM_COMMAND_RENAME, *name_file_or_dir_for_rename, name)

	*name_file_or_dir_for_rename = ""

	if result != 0 {
		return send_message(s, "503 Bad sequence of commands.\r\n")
	} else {
		return send_message(s, "250 Requested file action okay, file renamed.\r\n")
	}
}

// Client sent MFMT command, returns false if connection ended.
func command_mfmt(s TcpStream, receive_buffer []byte) bool {
	/*    var mdya string

	      remove_command(receive_buffer, &mdya, 4)

	      var v []string = strings.Split(mdya, " ")

	      var date_time_mfmt = v[0]

	      //var date_time_for_file = NaiveDateTime::parse_from_str(date_time_mfmt, "%Y%m%d%H%M%S").unwrap();

	      var file_name = string(receive_buffer[19:])

	      //var mtime = FileTime::from_unix_time(date_time_for_file.and_utc().timestamp(), 0);

	      var _ = set_file_mtime(file_name.clone(), mtime)

	      var send_buffer = fmt.Sprintf("213 Modify=%s; %s\r\n", date_time_mfmt, file_name)

	      return send_message(s, send_buffer)*/
	return true
}

// Client sent unknown command, returns false if fails.
func command_unknown(s TcpStream) bool {
	return send_message(s, "550 unrecognised command.\r\n")
}

// Takes a string with a 4 letter command at beginning and saves an output string with this removed.
func remove_command(input_string []byte, output_string *string, skip_characters uint) {
	*output_string = string(input_string[(skip_characters + 1):])
}

// Check is inputted string is valid email address (only requires an '@' before a '.').
func is_email_address(address string) bool {
	// First character must be a-z or A-Z.
	if !is_alphabetical(address[0]) {
		return false
	}

	var at_index int = -1
	var dot_index int = -1

	var length int = len(address)
	var i int = 1

	for i < length {
		var c = address[i]

		if !is_alphabetical(c) && !is_numerical(c) {
			if c == '@' {
				at_index = i
			} else if c == '.' {
				dot_index = i
			} else {
				return false
			}
		}
		i++
	}

	return at_index != -1 && dot_index != -1 && at_index < dot_index
}

// Returns true if the character is alphabetical.
func is_alphabetical(c uint8) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Returns true if the character is a number.
func is_numerical(c uint8) bool {
	return c >= '0' && c <= '9'
}

// Sends client the closing connection method and closes the socket.
func close_client_connection(s TcpStream) {
	send_message(s, "221 FTP server closed the connection.\r\n")

	s.Close()

	fmt.Println("Disconnected from client.")
}

// Replace '/' to '\' for Windows
func replace_backslash(buffer *string) {
	*buffer = strings.ReplaceAll(*buffer, "/", "\\")
}

// Converting cyrillic characters between Android and Windows 7
func simple_conv(in_string []byte, out_string *[]byte, tuda_suda bool) {
	const ALL_SYMBOLS_FOR_CONVERT uint = 31 + 31 + 4 + 1

	TABLE_FOR_CONVERT_TUDA := [][]byte{
		// small
		{0xd0, 0xb9, 0xE9, 0},
		{0xd1, 0x86, 0xF6, 0},
		{0xd1, 0x83, 0xF3, 0},
		{0xd0, 0xba, 0xEA, 0},
		{0xd0, 0xb5, 0xE5, 0},
		{0xd0, 0xbd, 0xED, 0},
		{0xd0, 0xb3, 0xE3, 0},
		{0xd1, 0x88, 0xF8, 0},
		{0xd1, 0x89, 0xF9, 0},
		{0xd0, 0xb7, 0xE7, 0},
		{0xd1, 0x85, 0xF5, 0},
		{0xd1, 0x84, 0xF4, 0},
		{0xd1, 0x8b, 0xFB, 0},
		{0xd0, 0xb2, 0xE2, 0},
		{0xd0, 0xb0, 0xE0, 0},
		{0xd0, 0xbf, 0xEF, 0},
		{0xd1, 0x80, 0xF0, 0},
		{0xd0, 0xbe, 0xEE, 0},
		{0xd0, 0xbb, 0xEB, 0},
		{0xd0, 0xb4, 0xE4, 0},
		{0xd0, 0xb6, 0xE6, 0},
		{0xd1, 0x8d, 0xFD, 0},
		{0xd1, 0x8f, 0xFF, 0},
		{0xd1, 0x87, 0xF7, 0},
		{0xd1, 0x81, 0xF1, 0},
		{0xd0, 0xbc, 0xEC, 0},
		{0xd0, 0xb8, 0xE8, 0},
		{0xd1, 0x82, 0xF2, 0},
		{0xd1, 0x8c, 0xFC, 0},
		{0xd0, 0xb1, 0xE1, 0},
		{0xd1, 0x8e, 0xFE, 0},
		// big
		{0xd0, 0x99, 0xC9, 0},
		{0xd0, 0xa6, 0xD6, 0},
		{0xd0, 0xa3, 0xD3, 0},
		{0xd0, 0x9a, 0xCA, 0},
		{0xd0, 0x95, 0xC5, 0},
		{0xd0, 0x9d, 0xCD, 0},
		{0xd0, 0x93, 0xC3, 0},
		{0xd0, 0xa8, 0xD8, 0},
		{0xd0, 0xa9, 0xD9, 0},
		{0xd0, 0x97, 0xC7, 0},
		{0xd0, 0xa5, 0xD5, 0},
		{0xd0, 0xa4, 0xD4, 0},
		{0xd0, 0xab, 0xDB, 0},
		{0xd0, 0x92, 0xC2, 0},
		{0xd0, 0x90, 0xC0, 0},
		{0xd0, 0x9f, 0xCF, 0},
		{0xd0, 0xa0, 0xD0, 0},
		{0xd0, 0x9e, 0xCE, 0},
		{0xd0, 0x9b, 0xCB, 0},
		{0xd0, 0x94, 0xC4, 0},
		{0xd0, 0x96, 0xC6, 0},
		{0xd0, 0xad, 0xDD, 0},
		{0xd0, 0xaf, 0xDF, 0},
		{0xd0, 0xa7, 0xD7, 0},
		{0xd0, 0xa1, 0xD1, 0},
		{0xd0, 0x9c, 0xCC, 0},
		{0xd0, 0x98, 0xC8, 0},
		{0xd0, 0xa2, 0xD2, 0},
		{0xd0, 0xac, 0xDC, 0},
		{0xd0, 0x91, 0xC1, 0},
		{0xd0, 0xae, 0xDE, 0},

		{0xd0, 0xaa, 0xda, 0}, // big "b
		{0xd1, 0x8a, 0xfa, 0}, // small "b
		{0xd0, 0x81, 0xa8, 0}, // big :E
		{0xd1, 0x91, 0xb8, 0}, // small :e

		{0xe2, 0x84, 0x96, 0xb9}} // N

	TABLE_FOR_CONVERT_SUDA := [][]byte{
		// small
		{0xd0, 0xb9, 0xA9, 0},
		{0xd1, 0x86, 0xE6, 0},
		{0xd1, 0x83, 0xE3, 0},
		{0xd0, 0xba, 0xAA, 0},
		{0xd0, 0xb5, 0xA5, 0},
		{0xd0, 0xbd, 0xAD, 0},
		{0xd0, 0xb3, 0xA3, 0},
		{0xd1, 0x88, 0xE8, 0},
		{0xd1, 0x89, 0xE9, 0},
		{0xd0, 0xb7, 0xA7, 0},
		{0xd1, 0x85, 0xE5, 0},
		{0xd1, 0x84, 0xE4, 0},
		{0xd1, 0x8b, 0xEB, 0},
		{0xd0, 0xb2, 0xA2, 0},
		{0xd0, 0xb0, 0xA0, 0},
		{0xd0, 0xbf, 0xAF, 0},
		{0xd1, 0x80, 0xE0, 0},
		{0xd0, 0xbe, 0xAE, 0},
		{0xd0, 0xbb, 0xAB, 0},
		{0xd0, 0xb4, 0xA4, 0},
		{0xd0, 0xb6, 0xA6, 0},
		{0xd1, 0x8d, 0xED, 0},
		{0xd1, 0x8f, 0xEF, 0},
		{0xd1, 0x87, 0xE7, 0},
		{0xd1, 0x81, 0xE1, 0},
		{0xd0, 0xbc, 0xAC, 0},
		{0xd0, 0xb8, 0xA8, 0},
		{0xd1, 0x82, 0xE2, 0},
		{0xd1, 0x8c, 0xEC, 0},
		{0xd0, 0xb1, 0xA1, 0},
		{0xd1, 0x8e, 0xEE, 0},
		// big
		{0xd0, 0x99, 0x89, 0},
		{0xd0, 0xa6, 0x96, 0},
		{0xd0, 0xa3, 0x93, 0},
		{0xd0, 0x9a, 0x8A, 0},
		{0xd0, 0x95, 0x85, 0},
		{0xd0, 0x9d, 0x8D, 0},
		{0xd0, 0x93, 0x83, 0},
		{0xd0, 0xa8, 0x98, 0},
		{0xd0, 0xa9, 0x99, 0},
		{0xd0, 0x97, 0x87, 0},
		{0xd0, 0xa5, 0x95, 0},
		{0xd0, 0xa4, 0x94, 0},
		{0xd0, 0xab, 0x9B, 0},
		{0xd0, 0x92, 0x82, 0},
		{0xd0, 0x90, 0x80, 0},
		{0xd0, 0x9f, 0x8F, 0},
		{0xd0, 0xa0, 0x90, 0},
		{0xd0, 0x9e, 0x8E, 0},
		{0xd0, 0x9b, 0x8B, 0},
		{0xd0, 0x94, 0x84, 0},
		{0xd0, 0x96, 0x86, 0},
		{0xd0, 0xad, 0x9D, 0},
		{0xd0, 0xaf, 0x9F, 0},
		{0xd0, 0xa7, 0x97, 0},
		{0xd0, 0xa1, 0x91, 0},
		{0xd0, 0x9c, 0x8C, 0},
		{0xd0, 0x98, 0x88, 0},
		{0xd0, 0xa2, 0x92, 0},
		{0xd0, 0xac, 0x9C, 0},
		{0xd0, 0x91, 0x81, 0},
		{0xd0, 0xae, 0x9E, 0},

		{0xd0, 0xaa, 0xda, 0}, // big "b
		{0xd1, 0x8a, 0xfa, 0}, // small "b
		{0xd0, 0x81, 0xa8, 0}, // big :E
		{0xd1, 0x91, 0xb8, 0}, // small :e

		{0xe2, 0x84, 0x96, 0xfc}} // N

	var in_len = len(in_string)

	if is_debug() {
		for _, x := range []byte(in_string) {
			fmt.Printf("0x%02x, ", x)
		}
		fmt.Println("")
	}

	var i int
	var b byte

	if tuda_suda {
		for i < in_len {
			if '\xd0' == in_string[i] || '\xd1' == in_string[i] {
				var is_found = false
				var q uint

				for q < ALL_SYMBOLS_FOR_CONVERT-1 {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] {
						b = TABLE_FOR_CONVERT_TUDA[q][2]
						*out_string = append(*out_string, b)
						is_found = true
						break
					}

					q += 1
				}

				if is_found {
					i += 1
				}
			} else if '\xe2' == in_string[i] {
				var is_found = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_TUDA[q][0] == in_string[i] && TABLE_FOR_CONVERT_TUDA[q][1] == in_string[i+1] && TABLE_FOR_CONVERT_TUDA[q][2] == in_string[i+2] {
						b = TABLE_FOR_CONVERT_TUDA[q][3]
						*out_string = append(*out_string, b)
						is_found = true
						break
					}

					q += 1
				}

				if is_found {
					i += 2
				}
			} else {
				*out_string = append(*out_string, byte(in_string[i]))
			}

			i += 1
		}
	} else {
		for i < in_len {
			var is_found = false
			var q uint

			for q < ALL_SYMBOLS_FOR_CONVERT-1 {
				if TABLE_FOR_CONVERT_SUDA[q][2] == in_string[i] {
					b = TABLE_FOR_CONVERT_SUDA[q][0]
					*out_string = append(*out_string, b)
					b = TABLE_FOR_CONVERT_SUDA[q][1]
					*out_string = append(*out_string, b)
					is_found = true
					break
				}
				q += 1
			}

			if !is_found {
				var is_found2 = false
				var q = ALL_SYMBOLS_FOR_CONVERT - 1

				for q < ALL_SYMBOLS_FOR_CONVERT {
					if TABLE_FOR_CONVERT_SUDA[q][3] == in_string[i] {
						b = TABLE_FOR_CONVERT_SUDA[q][0]
						*out_string = append(*out_string, b)
						b = TABLE_FOR_CONVERT_SUDA[q][1]
						*out_string = append(*out_string, b)
						b = TABLE_FOR_CONVERT_SUDA[q][2]
						*out_string = append(*out_string, b)
						is_found2 = true
						break
					}
					q += 1
				}

				if !is_found2 {
					*out_string = append(*out_string, byte(in_string[i]))
				}
			}

			i += 1
		}
	}

	if is_debug() {
		for _, x := range []byte(in_string) {
			fmt.Printf("0x%02x, ", x)
		}
		fmt.Println("")
	}
}
