import { useState } from 'react';
import { Container, Row, Col, InputGroup, Form, Button, Spinner } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

const Home = () => {

    const navigate = useNavigate()

    const [url, setUrl] = useState("");
    const [loading, setLoading] = useState(false)

    const handleScan = async () => {
        if(!url){
            return alert("Please enter a valid URL");
        }
        setLoading(true);

        try{
            const response = await axios.post("http://127.0.0.1:8000/scan", {
                "url" : url
            })

            navigate("/results", {
                "state" : {
                    "report" : response.data,
                    "target_url" : url
                }
            })
            setLoading(false);

        } catch (e){
            alert(`Error while posting: ${e.message}`);
            setLoading(false);
        }
    };

    return (
        <Container className='p-3 vh-100 d-flex align-items-center justify-content-center'>
            <Row className='flex-column gap-4 text-center'>

                <Col>
                    <h1 className="gradient-text display-3 fw-bold">
                        Web Security Scanner
                    </h1>
                </Col>

                <Col>
                    <h5>Automated Vulnerability Scanning for Smarter Web Security.</h5>
                </Col>

                <Col>
                    <InputGroup>
                        <Form.Control
                        placeholder="Enter URL.."
                        aria-describedby="scan-btn"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        />

                        <Button id="scan-btn"
                        onClick={handleScan}
                        >
                            { loading ? <Spinner size='sm'></Spinner> : "Scan" }
                        </Button>
                    </InputGroup>
                </Col>

            </Row>
        </Container>
    )
}

export default Home;