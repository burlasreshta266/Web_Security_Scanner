import { useLocation, useNavigate } from 'react-router-dom';
import { Container, Button, Table, Navbar } from 'react-bootstrap';

const Results = () => {

    const location = useLocation();
    const navigate = useNavigate();
    
    const report = location.state?.report;
    const target_url = location.state?.target_url;

    const reportData = location.state?.report?.vulnerabilities;

    if (!reportData || Object.keys(reportData).length === 0) {
        return (
            <Container className="text-center mt-5 text-white">
                <h2>No Vulnerabilities Found</h2>
                <Button onClick={() => navigate('/')} className="mt-3">Back to Scanner</Button>
            </Container>
        );
    }

    return (
        <Container fluid>
            <Navbar className='p-3' variant='dark' expand="lg">
                <Container>

                    <Navbar.Brand onClick={() => navigate('/')} className="gradient-text fw-bold cursor-pointer">Web Security Scanner</Navbar.Brand>
                    <Navbar.Toggle />

                    <Navbar.Collapse className="justify-content-end">
                        <Button onClick={() => navigate('/')}>Home</Button>
                    </Navbar.Collapse>

                </Container>
            </Navbar>
                

            <Container className='text-center mt-3'>
                <div className='mt-4'>
                    <h5 className='text-info'>{target_url}</h5>
                </div>
            </Container>


            <Container className='mt-4 mb-3'>
                {Object.keys(reportData).map((type) => { return (
               
                    <Container className='mt-4' fluid>
                        <h5>{type} Issues</h5>

                        <Table hover striped responsive variant="dark">

                            <thead>
                                <tr>
                                    {reportData[type].length > 0 && Object.keys(reportData[type][0]).map((key) => (
                                        <th key={key}>{key.charAt(0).toUpperCase() + key.slice(1)}</th>
                                    ))}
                                </tr>
                            </thead>

                            <tbody>
                                {reportData[type].map((items) => (
                                    <tr key={items.id}>
                                        {Object.values(items).map((value, index) => (
                                            <td key={index}>{value}</td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>

                        </Table>
                    </Container>
                    
                )})}
            </Container>

        </Container>
    )
}

export default Results;