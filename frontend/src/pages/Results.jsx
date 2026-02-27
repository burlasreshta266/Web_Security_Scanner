import { useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import {
    Alert,
    Badge,
    Button,
    Card,
    Col,
    Container,
    ListGroup,
    Navbar,
    Row,
    Table,
} from 'react-bootstrap';

const severityVariant = {
    high: 'danger',
    medium: 'warning',
    low: 'success',
};

const formatLabel = (value) => value.replace(/_/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());

const Results = () => {
    const location = useLocation();
    const navigate = useNavigate();

    const report = location.state?.report;
    const targetUrl = location.state?.target_url;

    const findings = report?.findings ?? [];
    const summary = report?.summary;

    const groupedFindings = useMemo(() => {
        return findings.reduce((acc, finding) => {
            if (!acc[finding.type]) {
                acc[finding.type] = [];
            }
            acc[finding.type].push(finding);
            return acc;
        }, {});
    }, [findings]);

    const summaryCards = [
        { label: 'Total findings', value: summary?.total_findings ?? findings.length },
        { label: 'Scanned URLs', value: summary?.scanned_urls ?? '-' },
        { label: 'Risk categories', value: Object.keys(groupedFindings).length },
    ];

    if (!report) {
        return (
            <Container className="text-center mt-5 text-white">
                <Alert variant="dark" className="results-panel">
                    No scan results were found in this session.
                </Alert>
                <Button onClick={() => navigate('/')} className="mt-3">Back to Scanner</Button>
            </Container>
        );
    }

    return (
        <Container fluid className="pb-5">
            <Navbar className="p-3" variant="dark" expand="lg">
                <Container>
                    <Navbar.Brand onClick={() => navigate('/')} className="gradient-text fw-bold cursor-pointer">
                        Web Security Scanner
                    </Navbar.Brand>
                    <Navbar.Toggle />
                    <Navbar.Collapse className="justify-content-end">
                        <Button onClick={() => navigate('/')}>New Scan</Button>
                    </Navbar.Collapse>
                </Container>
            </Navbar>

            <Container className="mt-4">
                <Card className="results-panel border-0 mb-4">
                    <Card.Body>
                        <p className="text-uppercase text-secondary mb-1 small">Scan target</p>
                        <h4 className="text-info mb-0">{targetUrl || 'Unknown target'}</h4>
                    </Card.Body>
                </Card>

                <Row className="g-3 mb-4">
                    {summaryCards.map((item) => (
                        <Col key={item.label} md={4}>
                            <Card className="results-panel border-0 h-100">
                                <Card.Body>
                                    <p className="text-secondary mb-2">{item.label}</p>
                                    <h3 className="mb-0">{item.value}</h3>
                                </Card.Body>
                            </Card>
                        </Col>
                    ))}
                </Row>

                {findings.length === 0 ? (
                    <Alert variant="success" className="results-panel border-0 text-white">
                        Great news — no vulnerabilities were identified in this scan.
                    </Alert>
                ) : (
                    Object.entries(groupedFindings).map(([type, issues]) => (
                        <Card key={type} className="results-panel border-0 mb-4">
                            <Card.Body>
                                <div className="d-flex align-items-center justify-content-between mb-3">
                                    <h5 className="mb-0">{type} Findings</h5>
                                    <Badge bg="secondary">{issues.length}</Badge>
                                </div>

                                <Table hover responsive variant="dark" className="align-middle mb-0">
                                    <thead>
                                        <tr>
                                            <th style={{ minWidth: 190 }}>Issue</th>
                                            <th style={{ minWidth: 120 }}>Severity</th>
                                            <th style={{ minWidth: 320 }}>Details</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {issues.map((issue) => (
                                            <tr key={issue.id}>
                                                <td>{issue.title}</td>
                                                <td>
                                                    <Badge bg={severityVariant[issue.severity] || 'secondary'}>
                                                        {issue.severity}
                                                    </Badge>
                                                </td>
                                                <td>
                                                    <ListGroup variant="flush">
                                                        {Object.entries(issue.details || {}).map(([key, value]) => (
                                                            <ListGroup.Item
                                                                key={`${issue.id}-${key}`}
                                                                className="bg-transparent text-white px-0 py-1 border-0"
                                                            >
                                                                <strong>{formatLabel(key)}:</strong> {String(value)}
                                                            </ListGroup.Item>
                                                        ))}
                                                    </ListGroup>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </Table>
                            </Card.Body>
                        </Card>
                    ))
                )}
            </Container>
        </Container>
    );
};

export default Results;
