import typing

from ...types import IdentityAlgorithmClass


class SchemaManager(object):
    """
    Manager for schemas: specifications of attribute disclosure algorithm parameterization.
    """

    def __init__(self) -> None:
        """
        Create a new SchemaManager: no algorithms are loaded initially.
        """
        super(SchemaManager, self).__init__()

        self.formats: typing.Dict[str, typing.Dict[str, typing.Any]] = dict()
        self.algorithms: typing.Dict[str, IdentityAlgorithmClass] = dict()

    def get_algorithm_class(self, algorithm_name: str) -> IdentityAlgorithmClass:
        """
        Get the implementation belonging to a certain algorithm name.
        These are bound to either:

         - bonehexact: for exact value matches using "Evaluating 2-DNF Formulas on Ciphertexts" by Boneh et al.
         - pengbaorange: for range proofs using "An efficient range proof scheme." by K. Peng and F. Bao.
         - irmaexact: for exact value matches using the IRMA protocol.

        :param algorithm_name: the name of the algorithm.
        """
        if algorithm_name in self.algorithms:
            return self.algorithms[algorithm_name]
        # Lazy load
        if algorithm_name == "bonehexact":
            from ..wallet.bonehexact.algorithm import BonehExactAlgorithm
            algorithm: IdentityAlgorithmClass = BonehExactAlgorithm
        elif algorithm_name == "pengbaorange":
            from ..wallet.pengbaorange.algorithm import PengBaoRangeAlgorithm
            algorithm = PengBaoRangeAlgorithm
        elif algorithm_name == "irmaexact":
            from ..wallet.irmaexact.algorithm import IRMAExactAlgorithm
            algorithm = IRMAExactAlgorithm
        else:
            raise RuntimeError(f"Attempted to load unknown proof algorithm {algorithm_name}!")
        self.algorithms[algorithm_name] = algorithm
        return algorithm

    def register_schema(self, schema_name: str, algorithm_name: str, parameters: dict) -> None:
        """
        Register a schema specification.
        Each schema is defined by an algorithm and its parameterization.

        :param schema_name: the new schema name to claim.
        :param algorithm_name: the algorithm to use (see `get_algorithm_class()`).
        :param parameters: the dictionary specifying the parameters for the algorithm.
        """
        schema = {"algorithm": algorithm_name}
        schema.update(parameters)
        self.formats[schema_name] = schema

    def register_default_schemas(self) -> None:
        """
        Register all default formats to this SchemaManager.
        You will load:

            - id_metadata: 1024 bit space "exact" value match
            - id_metadata_big: 4096 bit space "exact" value match
            - id_metadata_huge: 9216 bit space "exact" value match
            - id_metadata_range_18plus: NIZKP over a commitment, showing it lies within [0, 18]
            - id_irma_nijmegen_address_1568208470: IRMA address data match, valid until 11 Sept 2019 13:27:50 GMT
            - id_irma_nijmegen_personalData_1568208470: IRMA personal data match, valid until 11 Sept 2019 13:27:50 GMT
            - id_irma_nijmegen_ageLimits_1568208470: IRMA age data match, valid until 11 Sept 2019 13:27:50 GMT
            - id_irma_nijmegen_bsn_1568208470: IRMA bsn data match, valid until 11 Sept 2019 13:27:50 GMT
        """
        from ..default_identity_formats import FORMATS
        for schema in FORMATS:
            self.register_schema(schema, FORMATS[schema]["algorithm"], FORMATS[schema])  # type:ignore

    def get_algorithm_instance(self, schema_name: str):
        """
        Get an algorithm instance from a schema name.

        :param schema_name: the schema to instantiate the algorithm from.
        """
        schema = self.formats[schema_name]
        return self.get_algorithm_class(schema["algorithm"])(schema_name, self.formats)
