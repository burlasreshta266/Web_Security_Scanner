import { Container, Row, Col, InputGroup, Form, Button } from 'react-bootstrap';

const Home = () => {
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
                        />

                        <Button id="scan-btn">
                            Scan
                        </Button>
                    </InputGroup>
                </Col>

            </Row>
        </Container>
    )
}

export default Home;