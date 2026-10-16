<?php
class Invoice extends MY_Controller {

    public function __construct() {
        parent::__construct();
        $this->load->database();
    }

    public function view($id) {
        $q = $this->db->query("SELECT * FROM invoices WHERE id = $id"); // LSA-EXPECT:SQLI LSA-EXPECT:BOLA
        $this->load->view('invoice', array('inv' => $q->row()));
    }

    public function mine($id) {
        $uid = $this->session->userdata('user_id');
        $q = $this->db->get_where('invoices', array('id' => $id, 'user_id' => $uid)); // LSA-EXPECT:SAFE-BOLA
        $this->load->view('invoice', array('inv' => $q->row()));
    }

    public function update() {
        $id = $this->input->post('invoice_id');
        $note = $this->input->post('note');
        $this->db->query("UPDATE invoices SET note = ? WHERE id = ?", array($note, $id)); // LSA-EXPECT:SAFE-SQL-NOFLAG LSA-EXPECT:BOLA
    }

    private function _helper() {}
}
