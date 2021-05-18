import React, { FC } from 'react';
import { Alert } from 'reactstrap';
import Graph from './Graph';
import { QueryParams, ExemplarData } from '../../types/types';
import { isPresent } from '../../utils';

interface GraphTabContentProps {
  data: any;
  exemplars: ExemplarData;
  stacked: boolean;
  useLocalTime: boolean;
  showExemplars: boolean;
  lastQueryParams: QueryParams | null;
}

export const GraphTabContent: FC<GraphTabContentProps> = ({
  data,
  exemplars,
  stacked,
  useLocalTime,
  lastQueryParams,
  showExemplars,
}) => {
  if (!isPresent(data)) {
    return <Alert color="light">No data queried yet</Alert>;
  }
  if (data.result.length === 0) {
    return <Alert color="secondary">Empty query result</Alert>;
  }
  if (data.resultType !== 'matrix') {
    return (
      <Alert color="danger">Query result is of wrong type '{data.resultType}', should be 'matrix' (range vector).</Alert>
    );
  }
  return (
    <Graph
      data={data}
      exemplars={exemplars}
      stacked={stacked}
      useLocalTime={useLocalTime}
      showExemplars={showExemplars}
      queryParams={lastQueryParams}
    />
  );
};
